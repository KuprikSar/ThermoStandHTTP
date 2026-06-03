#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "protocol_examples_utils.h"
#include "mbedtls/base64.h"
#include "esp_rom_sys.h"   // для esp_rom_delay_us()
#include <esp_http_server.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_check.h"
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "hal/gpio_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>
#if !CONFIG_IDF_TARGET_LINUX
#include <esp_wifi.h>
#include <esp_system.h>
#include "nvs_flash.h"
#endif  // !CONFIG_IDF_TARGET_LINUX

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN  (64)

#define MAX31865_BANK_COUNT      2
#define MAX31865_PER_BANK        16
#define MAX31865_NUM_SENSORS     (MAX31865_BANK_COUNT * MAX31865_PER_BANK)

#define MAX31865_SPI_CLOCK_HZ    1000000
#define MAX31865_SPI_MODE        1

typedef struct
{
    gpio_num_t a0;
    gpio_num_t a1;
    gpio_num_t a2;
    gpio_num_t a3;
    gpio_num_t en;   // CS/EN вход IN74HC154, активный низкий. Например pin 18, pin 19 на GND.
} decoder154_t;

typedef struct
{
    spi_host_device_t host;
    spi_device_handle_t dev;

    gpio_num_t miso;  // SDO MAX31865
    gpio_num_t mosi;  // SDI MAX31865
    gpio_num_t sclk;  // CLK MAX31865

    decoder154_t dec;
} max31865_bank_t;

static max31865_bank_t g_banks[MAX31865_BANK_COUNT] =
{
    // Банк 0: датчики CH1..CH16, SPI2_HOST, первый IN74HC154
    {
        .host = SPI2_HOST,
        .miso = GPIO_NUM_13,  // SDO на плате сенсора
        .mosi = GPIO_NUM_11,  // SDI на плате сенсора
        .sclk = GPIO_NUM_12,  // CLK на плате сенсора
        .dec =
        {
            .a0 = GPIO_NUM_10,
            .a1 = GPIO_NUM_9,
            .a2 = GPIO_NUM_15,
            .a3 = GPIO_NUM_7,
            .en = GPIO_NUM_8,   // -> IN74HC154 #1 pin 18 CS1/EN, pin 19 CS2 -> GND
        },
    },

    // Банк 1: датчики CH17..CH32, SPI3_HOST, второй IN74HC154
    // ВАЖНО: GPIO ниже проверь по своей разводке и при необходимости замени.
    {
        .host = SPI3_HOST,
        .miso = GPIO_NUM_37,  // SDO на плате сенсора
        .mosi = GPIO_NUM_36,  // SDI на плате сенсора
        .sclk = GPIO_NUM_38,  // CLK на плате сенсора
        .dec =
        {
            .a0 = GPIO_NUM_18,
            .a1 = GPIO_NUM_17,
            .a2 = GPIO_NUM_16,
            .a3 = GPIO_NUM_6,
            .en = GPIO_NUM_5,   // -> IN74HC154 #2 pin 18 CS1/EN, pin 19 CS2 -> GND
        },
    },
};

static volatile float g_temp_c[MAX31865_NUM_SENSORS];   // температуры по каналам
static uint32_t g_fault_log_count[MAX31865_NUM_SENSORS];

#define MAX31865_RREF           430.0f      // опорный резистор, Ом
#define MAX31865_RTD_NOMINAL    100.0f      // PT100

// Регистры
#define MAX31865_REG_CONFIG         0x00
#define MAX31865_REG_RTD_MSB        0x01
#define MAX31865_REG_RTD_LSB        0x02
#define MAX31865_REG_FAULT_STATUS   0x07

#define MAX31865_CONFIG_BIAS        (1 << 7)
#define MAX31865_CONFIG_AUTO_CONV   (1 << 6)
#define MAX31865_CONFIG_1SHOT       (1 << 5)
#define MAX31865_CONFIG_3WIRE       (1 << 4)
#define MAX31865_CONFIG_FAULT_CLEAR (1 << 1)
#define MAX31865_CONFIG_FILTER_50HZ (1 << 0)  // 1 = 50 Гц, 0 = 60 Гц

//static spi_device_handle_t max31865_handle;
//static volatile float g_temp_ch1_c = NAN; // Глобальная температура, которую будем показывать в таблице
static const char *TAG = "example";

#if CONFIG_EXAMPLE_BASIC_AUTH

typedef struct 
{
    char    *username;
    char    *password;
} basic_auth_info_t;

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

static char *http_auth_basic(const char *username, const char *password)
{
    size_t out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    int rc = asprintf(&user_info, "%s:%s", username, password);
    if (rc < 0) 
    {
        ESP_LOGE(TAG, "asprintf() returned: %d", rc);
        return NULL;
    }

    if (!user_info) 
    {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    mbedtls_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
    */
    digest = calloc(1, 6 + n + 1);
    if (digest) 
    {
        strcpy(digest, "Basic ");
        mbedtls_base64_encode((unsigned char *)digest + 6, n, &out, (const unsigned char *)user_info, strlen(user_info));
    }
    free(user_info);
    return digest;
}

/* An HTTP GET handler */
static esp_err_t basic_auth_get_handler(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;
    basic_auth_info_t *basic_auth_info = req->user_ctx;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1) {
        buf = calloc(1, buf_len);
        if (!buf) {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) 
        {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        } else 
        {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
        if (!auth_credentials) {
            ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
            free(buf);
            return ESP_ERR_NO_MEM;
        }

        if (strncmp(auth_credentials, buf, buf_len)) 
        {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
        } else 
        {
            ESP_LOGI(TAG, "Authenticated!");
            char *basic_auth_resp = NULL;
            httpd_resp_set_status(req, HTTPD_200);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            int rc = asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
            if (rc < 0) 
            {
                ESP_LOGE(TAG, "asprintf() returned: %d", rc);
                free(auth_credentials);
                return ESP_FAIL;
            }
            if (!basic_auth_resp) 
            {
                ESP_LOGE(TAG, "No enough memory for basic authorization response");
                free(auth_credentials);
                free(buf);
                return ESP_ERR_NO_MEM;
            }
            httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
            free(basic_auth_resp);
        }
        free(auth_credentials);
        free(buf);
    } else 
    {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return ESP_OK;
}

static httpd_uri_t basic_auth = 
{
    .uri       = "/basic_auth",
    .method    = HTTP_GET,
    .handler   = basic_auth_get_handler,
};

static void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (basic_auth_info) 
    {
        basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        basic_auth.user_ctx = basic_auth_info;
        httpd_register_uri_handler(server, &basic_auth);
    }
}
#endif

static const char index_html[] =
"<!DOCTYPE html>"
"<html lang='ru'>"
"<head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
"<title>ESP32-S3 PT100</title>"
"<style>"
"body{font-family:Arial,Helvetica,sans-serif;margin:16px;background:#f7f7f7;}"
"h1{font-size:42px;margin:0 0 12px 0;}"
"h2{font-size:24px;margin:8px 0;}"
".stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;font-size:20px;}"
".stat-card{background:white;border:1px solid #ccc;border-radius:8px;padding:10px 14px;min-width:115px;box-shadow:0 1px 3px rgba(0,0,0,0.08);}"
".tables{display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap;}"
"table{border-collapse:collapse;background:white;font-size:22px;min-width:430px;box-shadow:0 1px 3px rgba(0,0,0,0.08);}"
"th,td{border:1px solid #ccc;padding:8px 14px;text-align:center;}"
"th{background:#e9e9e9;font-weight:bold;}"
"td.temp{text-align:right;font-variant-numeric:tabular-nums;}"
".ok{background:#d9f7d9;}"
".warn{background:#fff3b0;}"
".hot{background:#ffb3b3;}"
".err{background:#e0e0e0;color:#b00000;font-weight:bold;}"
".off{background:#eeeeee;color:#777;}"
".small{font-size:14px;color:#666;margin-top:12px;}"
"</style>"
"</head>"
"<body>"
"<h1>Температурные датчики PT100</h1>"
"<div class='stats'>"
"<div class='stat-card'>OK: <b id='stat-ok'>0</b></div>"
"<div class='stat-card'>WARN: <b id='stat-warn'>0</b></div>"
"<div class='stat-card'>HOT: <b id='stat-hot'>0</b></div>"
"<div class='stat-card'>ERR: <b id='stat-err'>0</b></div>"
"<div class='stat-card'>OFF: <b id='stat-off'>0</b></div>"
"<div class='stat-card'>Обновление: <b id='last-update'>--</b></div>"
"</div>"
"<div class='tables'>"
"<div>"
"<h2>Каналы CH1...CH16</h2>"
"<table>"
"<thead><tr><th>Канал</th><th>Температура, °C</th><th>Статус</th></tr></thead>"
"<tbody id='table-1'></tbody>"
"</table>"
"</div>"
"<div>"
"<h2>Каналы CH17...CH32</h2>"
"<table>"
"<thead><tr><th>Канал</th><th>Температура, °C</th><th>Статус</th></tr></thead>"
"<tbody id='table-2'></tbody>"
"</table>"
"</div>"
"</div>"
"<div class='small'>Данные обновляются без перезагрузки страницы</div>"
"<script>"
"function statusFromTemp(ch){"
"if(!ch.enabled)return{text:'OFF',cls:'off'};"
"if(!ch.valid)return{text:'ERR',cls:'err'};"
"if(ch.temp>100.0)return{text:'HOT',cls:'hot'};"
"if(ch.temp>=80.0)return{text:'WARN',cls:'warn'};"
"if(ch.temp>=0.0)return{text:'OK',cls:'ok'};"
"return{text:'ERR',cls:'err'};"
"}"
"function makeRow(ch){"
"const st=statusFromTemp(ch);"
"const tempText=(ch.enabled&&ch.valid)?ch.temp.toFixed(1):'--';"
"return `<tr class='${st.cls}'>`+`<td>CH${ch.ch}</td>`+`<td class='temp'>${tempText}</td>`+`<td>${st.text}</td>`+`</tr>`;"
"}"
"async function updateData(){"
"try{"
"const response=await fetch('/api/temps',{cache:'no-store'});"
"const data=await response.json();"
"let html1='',html2='';"
"let cntOk=0,cntWarn=0,cntHot=0,cntErr=0,cntOff=0;"
"data.channels.forEach(ch=>{"
"const st=statusFromTemp(ch);"
"if(st.text==='OK')cntOk++;"
"else if(st.text==='WARN')cntWarn++;"
"else if(st.text==='HOT')cntHot++;"
"else if(st.text==='ERR')cntErr++;"
"else if(st.text==='OFF')cntOff++;"
"if(ch.ch<=16)html1+=makeRow(ch);else html2+=makeRow(ch);"
"});"
"document.getElementById('table-1').innerHTML=html1;"
"document.getElementById('table-2').innerHTML=html2;"
"document.getElementById('stat-ok').textContent=cntOk;"
"document.getElementById('stat-warn').textContent=cntWarn;"
"document.getElementById('stat-hot').textContent=cntHot;"
"document.getElementById('stat-err').textContent=cntErr;"
"document.getElementById('stat-off').textContent=cntOff;"
"document.getElementById('last-update').textContent=new Date().toLocaleTimeString();"
"}catch(e){document.getElementById('last-update').textContent='ошибка связи';}"
"}"
"updateData();"
"setInterval(updateData,1000);"
"</script>"
"</body>"
"</html>";

static inline int max31865_get_bank(int idx)
{
    return idx / MAX31865_PER_BANK;
}

static inline int max31865_get_channel(int idx)
{
    return idx % MAX31865_PER_BANK;
}

static void decoder154_disable(const decoder154_t *dec)
{
    gpio_set_level(dec->en, 1);   // все Y0..Y15 = 1, все MAX31865 не выбраны
}

static void decoder154_enable(const decoder154_t *dec)
{
    gpio_set_level(dec->en, 0);   // выбранный Yx = 0
}

static void decoder154_set_addr(const decoder154_t *dec, uint8_t ch)
{
    gpio_set_level(dec->a0, (ch >> 0) & 1);
    gpio_set_level(dec->a1, (ch >> 1) & 1);
    gpio_set_level(dec->a2, (ch >> 2) & 1);
    gpio_set_level(dec->a3, (ch >> 3) & 1);
}

static esp_err_t decoder154_init(const decoder154_t *dec)
{
    uint64_t mask =
        (1ULL << dec->a0) |
        (1ULL << dec->a1) |
        (1ULL << dec->a2) |
        (1ULL << dec->a3) |
        (1ULL << dec->en);

    gpio_config_t io_conf =
    {
        .pin_bit_mask = mask,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    ESP_RETURN_ON_ERROR(gpio_config(&io_conf), TAG, "gpio_config(decoder154) failed");

    // На старте обязательно выключаем дешифратор. Желательно еще иметь внешнюю подтяжку EN/CS1 10 кОм к 3.3 В.
    decoder154_disable(dec);
    decoder154_set_addr(dec, 0);

    return ESP_OK;
}

static esp_err_t max31865_spi_init(void)
{
    for (int bank = 0; bank < MAX31865_BANK_COUNT; bank++)
    {
        max31865_bank_t *b = &g_banks[bank];

        ESP_RETURN_ON_ERROR(decoder154_init(&b->dec), TAG, "decoder154_init failed");

        spi_bus_config_t buscfg =
        {
            .mosi_io_num = b->mosi,
            .miso_io_num = b->miso,
            .sclk_io_num = b->sclk,
            .quadwp_io_num = -1,
            .quadhd_io_num = -1,
            .max_transfer_sz = 32,
        };

        ESP_RETURN_ON_ERROR(spi_bus_initialize(b->host, &buscfg, SPI_DMA_CH_AUTO),
                            TAG, "spi_bus_initialize bank %d failed", bank);

        spi_device_interface_config_t devcfg =
        {
            .clock_speed_hz = MAX31865_SPI_CLOCK_HZ,
            .mode = MAX31865_SPI_MODE,
            .spics_io_num = -1,     // CS вручную через IN74HC154
            .queue_size = 1,
        };

        ESP_RETURN_ON_ERROR(spi_bus_add_device(b->host, &devcfg, &b->dev),
                            TAG, "spi_bus_add_device bank %d failed", bank);
    }

    for (int i = 0; i < MAX31865_NUM_SENSORS; i++)
    {
        g_temp_c[i] = NAN;
    }

    return ESP_OK;
}

static inline void max31865_select(int idx)
{
    int bank = max31865_get_bank(idx);
    int ch = max31865_get_channel(idx);
    decoder154_t *dec = &g_banks[bank].dec;

    // Защита от глитчей: сначала выключаем 74HC154, потом меняем A0..A3, потом включаем.
    decoder154_disable(dec);
    decoder154_set_addr(dec, (uint8_t)ch);
    esp_rom_delay_us(1);
    decoder154_enable(dec);
    esp_rom_delay_us(2);
}

static inline void max31865_deselect(int idx)
{
    int bank = max31865_get_bank(idx);
    decoder154_disable(&g_banks[bank].dec);
    esp_rom_delay_us(1);
}

static esp_err_t max31865_transmit(int idx, spi_transaction_t *t)
{
    if (idx < 0 || idx >= MAX31865_NUM_SENSORS)
    {
        return ESP_ERR_INVALID_ARG;
    }

    int bank = max31865_get_bank(idx);

    max31865_select(idx);
    esp_err_t ret = spi_device_transmit(g_banks[bank].dev, t);
    max31865_deselect(idx);

    return ret;
}

static esp_err_t max31865_write_reg(int idx, uint8_t reg, uint8_t value)
{
    uint8_t data[2] = { (uint8_t)(reg | 0x80), value };

    spi_transaction_t t = {
        .length = 16,
        .tx_buffer = data,
    };

    return max31865_transmit(idx, &t);
}

static esp_err_t max31865_read_regs(int idx, uint8_t reg, uint8_t *buf, size_t len)
{
    if (len + 1 > 8) return ESP_ERR_INVALID_ARG;

    uint8_t data[8] = {0};
    data[0] = reg & 0x7F;

    spi_transaction_t t = 
    {
        .length = (len + 1) * 8,
        .tx_buffer = data,
        .rx_buffer = data,
    };

    esp_err_t ret = max31865_transmit(idx, &t);

    if (ret != ESP_OK) return ret;
    memcpy(buf, &data[1], len);
    return ESP_OK;
}

static esp_err_t max31865_read_fault(int idx, uint8_t *fault)
{
    return max31865_read_regs(idx, MAX31865_REG_FAULT_STATUS, fault, 1);
}

static esp_err_t max31865_read_rtd16(int idx, uint16_t *rtd16)
{
    uint8_t buf[2];
    ESP_RETURN_ON_ERROR(max31865_read_regs(idx, MAX31865_REG_RTD_MSB, buf, 2),
                        TAG, "read RTD failed");
    *rtd16 = ((uint16_t)buf[0] <<8) | buf[1];
    return ESP_OK;
}

static esp_err_t max31865_configure(int idx)
{
    uint8_t cfg = 0;
    cfg |= MAX31865_CONFIG_BIAS;
    cfg |= MAX31865_CONFIG_AUTO_CONV;
    cfg |= MAX31865_CONFIG_FILTER_50HZ;
    cfg |= MAX31865_CONFIG_FAULT_CLEAR;
    return max31865_write_reg(idx, MAX31865_REG_CONFIG, cfg);
}

static esp_err_t max31865_read_rtd_raw(int idx, uint16_t *rtd)
{
    uint16_t rtd16;
    ESP_RETURN_ON_ERROR(max31865_read_rtd16(idx, &rtd16), TAG, "read RTD16 failed");

    // bit0 в LSB = fault
    if (rtd16 & 0x0001) {
        uint8_t fault = 0;
        (void)max31865_read_fault(idx, &fault);

        // Не спамим UART каждую секунду по всем не подключенным каналам.
        // Частый ESP_LOGW внутри задачи тоже заметно ест стек.
        if (idx >= 0 && idx < MAX31865_NUM_SENSORS && g_fault_log_count[idx] < 3) {
            g_fault_log_count[idx]++;
            ESP_LOGW(TAG, "CH%d fault! RTD16=0x%04X faultReg=0x%02X", idx + 1, rtd16, fault);
        }

        return ESP_FAIL;
    }

    *rtd = (rtd16 >> 1);
    return ESP_OK;
}


// Переводим код АЦП в температуру по Callendar–Van Dusen для 0..850 °C
static float max31865_rtd_to_celsius(uint16_t rtd)
{
    const float a = 3.9083e-3f;
    const float b = -5.775e-7f;

    float r = (float)rtd * MAX31865_RREF / 32768.0f; // 15 бит значащих
    float z = r / MAX31865_RTD_NOMINAL;

    float c = 1.0f - z;
    float D = a * a - 4.0f * b * c;

    if (D < 0.0f) {
        return NAN;
    }

    float temp = (-a + sqrtf(D)) / (2.0f * b);
    return temp; // для отрицательных температур понадобится другая формула
}

static float max31865_read_temperature_c(int idx)
{
    uint16_t rtd;
    if (max31865_read_rtd_raw(idx, &rtd) != ESP_OK) return NAN;
    return max31865_rtd_to_celsius(rtd);
}

// Задача, которая раз в секунду обновляет температуры одной SPI-банки
static void max31865_bank_task(void *arg)
{
    int bank = (int)(intptr_t)arg;
    int first_sensor = bank * MAX31865_PER_BANK;

    vTaskDelay(pdMS_TO_TICKS(200)); // дать время на первые конверсии после конфигурации

    while (1)
    {
        for (int ch = 0; ch < MAX31865_PER_BANK; ch++)
        {
            int sensor_index = first_sensor + ch;
            g_temp_c[sensor_index] = max31865_read_temperature_c(sensor_index);
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

/* Главная HTML страница */
static esp_err_t index_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, index_html, HTTPD_RESP_USE_STRLEN);
}

static bool temp_value_is_valid(float t)
{
    if (isnan(t)) {
        return false;
    }

    // Для этого стенда отрицательные температуры считаем ошибкой.
    // Верхний предел оставлен с запасом под PT100/MAX31865.
    if (t < 0.0f || t > 850.0f) {
        return false;
    }

    return true;
}

/* JSON API для обновления таблицы без перезагрузки страницы */
static esp_err_t temps_api_get_handler(httpd_req_t *req)
{
    // Важно: буфер static, чтобы не класть 4 КБ на стек задачи httpd.
    // Еще важнее: не используем %.2f в snprintf, потому что float -> text
    // через _dtoa_r оказался тяжелым для стека на ESP32-S3.
    static char json[4096];
    int len = 0;

    len += snprintf(json + len, sizeof(json) - len, "{\"channels\":[");

    for (int i = 0; i < MAX31865_NUM_SENSORS; i++)
    {
        float t = g_temp_c[i];
        bool enabled = true;
        bool valid = temp_value_is_valid(t);

        if (i > 0) {
            len += snprintf(json + len, sizeof(json) - len, ",");
        }

        // JSON temp делаем без float printf: 24.3 -> целые десятые.
        int temp_x10 = 0;
        if (valid) {
            temp_x10 = (int)(t * 10.0f + 0.5f);
        }

        int temp_int = temp_x10 / 10;
        int temp_frac = temp_x10 % 10;

        len += snprintf(json + len, sizeof(json) - len,
                        "{\"ch\":%d,\"temp\":%d.%d,\"valid\":%s,\"enabled\":%s}",
                        i + 1,
                        temp_int,
                        temp_frac,
                        valid ? "true" : "false",
                        enabled ? "true" : "false");

        if (len < 0 || len >= (int)sizeof(json)) {
            httpd_resp_send_500(req);
            return ESP_FAIL;
        }
    }

    len += snprintf(json + len, sizeof(json) - len, "]}");

    if (len < 0 || len >= (int)sizeof(json)) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, json, len);
}

static const httpd_uri_t index_root_uri =
{
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = index_get_handler,
    .user_ctx  = NULL
};

static const httpd_uri_t index_sensors_uri =
{
    .uri       = "/sensors",
    .method    = HTTP_GET,
    .handler   = index_get_handler,
    .user_ctx  = NULL
};

static const httpd_uri_t temps_api_uri =
{
    .uri       = "/api/temps",
    .method    = HTTP_GET,
    .handler   = temps_api_get_handler,
    .user_ctx  = NULL
};

/* An HTTP POST handler */
static esp_err_t echo_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;

    while (remaining > 0) 
    {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) 
        {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) 
            {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
    }

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t echo = 
{
    .uri       = "/echo",
    .method    = HTTP_POST,
    .handler   = echo_post_handler,
    .user_ctx  = NULL
};

/* An HTTP_ANY handler */
static esp_err_t any_handler(httpd_req_t *req)
{
    /* Send response with body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t any = 
{
    .uri       = "/any",
    .method    = HTTP_ANY,
    .handler   = any_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = "Hello World!"
};

/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /echo URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /echo is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /echo)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/sensors", req->uri) == 0) 
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/sensors URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    } else if (strcmp("/echo", req->uri) == 0) 
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

/* An HTTP PUT handler. This demonstrates realtime
 * registration and deregistration of URI handlers
 */
static esp_err_t ctrl_put_handler(httpd_req_t *req)
{
    char buf;
    int ret;

    if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) 
    {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) 
        {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    if (buf == '0') 
    {
        /* URI handlers can be unregistered using the uri string */
        ESP_LOGI(TAG, "Unregistering /sensors and /echo URIs");
        httpd_unregister_uri(req->handle, "/sensors");
        httpd_unregister_uri(req->handle, "/echo");
        /* Register the custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    else 
    {
        ESP_LOGI(TAG, "Registering /sensors and /echo URIs");
        httpd_register_uri_handler(req->handle, &index_sensors_uri);
        httpd_register_uri_handler(req->handle, &echo);
        /* Unregister custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
    }

    /* Respond with empty body */
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t ctrl = {
    .uri       = "/ctrl",
    .method    = HTTP_PUT,
    .handler   = ctrl_put_handler,
    .user_ctx  = NULL
};

#if CONFIG_EXAMPLE_ENABLE_SSE_HANDLER
/* An HTTP GET handler for SSE */
static esp_err_t sse_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/event-stream");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");

    char sse_data[64];
    while (1) {
        struct timeval tv;
        gettimeofday(&tv, NULL); // Get the current time
        int64_t time_since_boot = tv.tv_sec; // Time since boot in seconds
        esp_err_t err;
        int len = snprintf(sse_data, sizeof(sse_data), "data: Time since boot: %" PRIi64 " seconds\n\n", time_since_boot);
        if ((err = httpd_resp_send_chunk(req, sse_data, len)) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send sse data (returned %02X)", err);
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000)); // Send data every second
    }

    httpd_resp_send_chunk(req, NULL, 0); // End response
    return ESP_OK;
}

static const httpd_uri_t sse = {
    .uri       = "/sse",
    .method    = HTTP_GET,
    .handler   = sse_handler,
    .user_ctx  = NULL
};
#endif // CONFIG_EXAMPLE_ENABLE_SSE_HANDLER

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8192;
#if CONFIG_IDF_TARGET_LINUX
    // Setting port as 8001 when building for Linux. Port 80 can be used only by a privileged user in linux.
    // So when a unprivileged user tries to run the application, it throws bind error and the server is not started.
    // Port 8001 can be used by an unprivileged user as well. So the application will not throw bind error and the
    // server will be started.
    config.server_port = 8001;
#endif // !CONFIG_IDF_TARGET_LINUX
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &index_root_uri);
        httpd_register_uri_handler(server, &index_sensors_uri);
        httpd_register_uri_handler(server, &temps_api_uri);
        httpd_register_uri_handler(server, &echo);
        httpd_register_uri_handler(server, &ctrl);
        httpd_register_uri_handler(server, &any);
#if CONFIG_EXAMPLE_ENABLE_SSE_HANDLER
        httpd_register_uri_handler(server, &sse); // Register SSE handler
#endif
#if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
#endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

#if !CONFIG_IDF_TARGET_LINUX
static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ESP_LOGE(TAG, "Failed to stop http server");
        }
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}
#endif // !CONFIG_IDF_TARGET_LINUX

void app_main(void)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    /* Register event handlers to stop the server when Wi-Fi or Ethernet is disconnected,
     * and re-start it upon connection.
     */
#if !CONFIG_IDF_TARGET_LINUX
#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET
#endif // !CONFIG_IDF_TARGET_LINUX

    // --- Инициализация all MAX31865 + запуск задачи чтения температуры ---
    ESP_ERROR_CHECK(max31865_spi_init());

for (int i = 0; i < MAX31865_NUM_SENSORS; i++) 
{
    ESP_ERROR_CHECK(max31865_configure(i));
}
    xTaskCreate(max31865_bank_task, "max31865_bank0", 8192, (void *)(intptr_t)0, 5, NULL);
    xTaskCreate(max31865_bank_task, "max31865_bank1", 8192, (void *)(intptr_t)1, 5, NULL);


    /* Start the server for the first time */
    server = start_webserver();

    while (server) {
        sleep(5);
    }
}

