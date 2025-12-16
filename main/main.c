#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "protocol_examples_utils.h"
#include "esp_tls_crypto.h"
#include "esp_rom_sys.h"   // для esp_rom_delay_us()
#include <esp_http_server.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_tls.h"
#include "esp_check.h"
#include <time.h>
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
#include "esp_eth.h"
#endif  // !CONFIG_IDF_TARGET_LINUX

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN  (64)

#define MAX31865_SPI_HOST   SPI2_HOST    
#define MAX31865_PIN_MISO   GPIO_NUM_13  //SDO на плате сенсора
#define MAX31865_PIN_MOSI   GPIO_NUM_11  //SDI на плате сенсора
#define MAX31865_PIN_SCLK   GPIO_NUM_12  //CLK на плате сенсора
//#define MAX31865_PIN_CS     GPIO_NUM_10  //CS на плате сенсора

#define MAX31865_NUM_SENSORS 8

static const gpio_num_t MAX31865_CS_PINS[MAX31865_NUM_SENSORS] = 
{
    GPIO_NUM_10, GPIO_NUM_9, GPIO_NUM_15, GPIO_NUM_7,
    GPIO_NUM_8,  GPIO_NUM_18, GPIO_NUM_17, GPIO_NUM_16
};
//10-CH1, 9-CH2, 15-CH3, 7-CH4, 8-CH5, 18-CH6, 17-CH7, 16-CH8
static spi_device_handle_t max31865_handle;
static volatile float g_temp_c[MAX31865_NUM_SENSORS];   // температуры по каналам

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
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
    */
    digest = calloc(1, 6 + n + 1);
    if (digest) 
    {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, &out, (const unsigned char *)user_info, strlen(user_info));
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

static const char temps_page_html_fmt[] =
"<!DOCTYPE html>"
"<html>"
"<head>"
"  <meta charset=\"utf-8\">"
"  <meta http-equiv=\"refresh\" content=\"1\">"
"  <title>ESP32-S3 PT100</title>"
"  <style>"
"    body{font-family:Arial,Helvetica,sans-serif;margin:20px;}"
"    table{border-collapse:collapse;}"
"    th,td{border:1px solid #ccc;padding:6px 10px;text-align:center;}"
"    th{background:#f0f0f0;}"
"  </style>"
"</head>"
"<body>"
"  <h1>Температурные датчики PT100</h1>"
"  <table>"
"    <tr><th>#</th><th>Канал</th><th>Температура, &deg;C</th></tr>"
"    <tr><td>1</td><td>Position1</td><td id=\"t1\">%s</td></tr>"
"    <tr><td>2</td><td>Position2</td><td id=\"t2\">%s</td></tr>"
"    <tr><td>3</td><td>Position3</td><td id=\"t3\">%s</td></tr>"
"    <tr><td>4</td><td>Position4</td><td id=\"t4\">%s</td></tr>"
"    <tr><td>5</td><td>Position5</td><td id=\"t5\">%s</td></tr>"
"    <tr><td>6</td><td>Position6</td><td id=\"t6\">%s</td></tr>"
"    <tr><td>7</td><td>Position7</td><td id=\"t7\">%s</td></tr>"
"    <tr><td>8</td><td>Position8</td><td id=\"t8\">%s</td></tr>"
"  </table>"
"</body>"
"</html>";

static esp_err_t max31865_spi_init(void)
{
    spi_bus_config_t buscfg = 
    {
        .mosi_io_num = MAX31865_PIN_MOSI,
        .miso_io_num = MAX31865_PIN_MISO,
        .sclk_io_num = MAX31865_PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 0,
    };

    ESP_RETURN_ON_ERROR(spi_bus_initialize(MAX31865_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO),
                        TAG, "spi_bus_initialize failed");

    spi_device_interface_config_t devcfg = 
    {
        .clock_speed_hz = 1000000,
        .mode = 1,
        .spics_io_num = -1,     // CS будем дёргать вручную GPIO
        .queue_size = 1,
    };

    ESP_RETURN_ON_ERROR(spi_bus_add_device(MAX31865_SPI_HOST, &devcfg, &max31865_handle),
                        TAG, "spi_bus_add_device failed");

    // Настраиваем все CS как выходы и уводим в "1" (неактивно)
    uint64_t mask = 0;
    for (int i = 0; i < MAX31865_NUM_SENSORS; i++) 
    {
        mask |= (1ULL << MAX31865_CS_PINS[i]);
        g_temp_c[i] = NAN;
    }

    gpio_config_t io_conf = 
    {
        .pin_bit_mask = mask,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = 0,
        .pull_down_en = 0,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&io_conf), TAG, "gpio_config(CS) failed");

    for (int i = 0; i < MAX31865_NUM_SENSORS; i++) 
    {
        gpio_set_level(MAX31865_CS_PINS[i], 1);
    }

    return ESP_OK;
}

static inline void max31865_select(int idx)
{
    for (int i = 0; i < MAX31865_NUM_SENSORS; i++) {
        gpio_set_level(MAX31865_CS_PINS[i], 1);
    }
    gpio_set_level(MAX31865_CS_PINS[idx], 0);
    esp_rom_delay_us(2);
}


static inline void max31865_deselect(int idx)
{
    gpio_set_level(MAX31865_CS_PINS[idx], 1);
}


static esp_err_t max31865_write_reg(int idx, uint8_t reg, uint8_t value)
{
    uint8_t data[2] = { (uint8_t)(reg | 0x80), value };

    spi_transaction_t t = {
        .length = 16,
        .tx_buffer = data,
    };

    max31865_select(idx);
    esp_err_t ret = spi_device_transmit(max31865_handle, &t);
    max31865_deselect(idx);
    return ret;
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

    max31865_select(idx);
    esp_err_t ret = spi_device_transmit(max31865_handle, &t);
    max31865_deselect(idx);

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
    *rtd16 = ((uint16_t)buf[0] << 8) | buf[1];
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
        ESP_LOGW(TAG, "CH%d fault! RTD16=0x%04X faultReg=0x%02X", idx+1, rtd16, fault);
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

// Задача, которая раз в секунду обновляет глобальную температуру
static void max31865_task(void *arg)
{
    /*
    uint16_t rtd16 = 0;
    uint8_t fault = 0;

    ESP_ERROR_CHECK(max31865_read_rtd16(i, &rtd16));
    ESP_ERROR_CHECK(max31865_read_fault(i, &fault));

    ESP_LOGI(TAG, "CH%d: RTD16=0x%04X faultBit=%d faultReg=0x%02X",
         i+1, rtd16, (int)(rtd16 & 1), fault);
    */

    vTaskDelay(pdMS_TO_TICKS(200)); // дать время на первые конверсии после конфигурации

    while (1) 
    {
        for (int i = 0; i < MAX31865_NUM_SENSORS; i++) 
        {
            g_temp_c[i] = max31865_read_temperature_c(i);
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
        
}

/* An HTTP GET handler */
static esp_err_t hello_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;
   
    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1) 
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) 
        {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) 
        {
            ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1) 
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) 
        {
            ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) 
    {
        buf = malloc(buf_len);
        ESP_RETURN_ON_FALSE(buf, ESP_ERR_NO_MEM, TAG, "buffer alloc failed");
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) 
        {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN], dec_param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN] = {0};
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) 
            {
                ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) 
            {
                ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) 
            {
                ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
        }
        free(buf);
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

       httpd_resp_set_type(req, "text/html; charset=utf-8");

    // 8 датчиков -> 8 строк для подстановки в HTML
    char tbuf[MAX31865_NUM_SENSORS][16];

    for (int i = 0; i < MAX31865_NUM_SENSORS; i++) 
    {
        float t = g_temp_c[i];     // <-- ВАЖНО: берем из массива, не g_temp_ch1_c
        if (isnan(t)) 
        {
            strcpy(tbuf[i], "--");
        } else 
        {
            snprintf(tbuf[i], sizeof(tbuf[i]), "%.2f", t);
        }
    }

    // 1) Узнаём, сколько байт нужно под итоговую страницу (передаём 8 строк!)
    int len = snprintf(NULL, 0, temps_page_html_fmt,
                       tbuf[0], tbuf[1], tbuf[2], tbuf[3],
                       tbuf[4], tbuf[5], tbuf[6], tbuf[7]);
    if (len < 0) 
    {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // 2) Выделяем буфер
    char *page = malloc(len + 1);
    if (!page) 
    {
        httpd_resp_send_500(req);
        return ESP_ERR_NO_MEM;
    }

    // 3) Формируем страницу
    int written = snprintf(page, len + 1, temps_page_html_fmt,
                           tbuf[0], tbuf[1], tbuf[2], tbuf[3],
                           tbuf[4], tbuf[5], tbuf[6], tbuf[7]);
    if (written < 0 || written > len) 
    {
        free(page);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // 4) Отправляем ответ
    httpd_resp_send(req, page, len);
    free(page);




    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) 
    {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t hello = 
{
    .uri       = "/sensors",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
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
    if (strcmp("/hello", req->uri) == 0) 
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
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
        ESP_LOGI(TAG, "Unregistering /hello and /echo URIs");
        httpd_unregister_uri(req->handle, "/hello");
        httpd_unregister_uri(req->handle, "/echo");
        /* Register the custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    else 
    {
        ESP_LOGI(TAG, "Registering /hello and /echo URIs");
        httpd_register_uri_handler(req->handle, &hello);
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
        httpd_register_uri_handler(server, &hello);
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
    xTaskCreate(max31865_task, "max31865_task", 4096, NULL, 5, NULL);


    /* Start the server for the first time */
    server = start_webserver();

    while (server) {
        sleep(5);
    }
}

