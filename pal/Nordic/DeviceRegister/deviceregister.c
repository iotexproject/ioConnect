#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>


#include "include/utils/devRegister/devRegister.h"


#define MSG_SIZE 256

/* queue to store up to 10 messages (aligned to 4-byte boundary) */
K_MSGQ_DEFINE(uart_msgq, MSG_SIZE, 2, 4);

/* change this to any other UART peripheral if desired */
#define UART_DEVICE_NODE DT_CHOSEN(zephyr_shell_uart)
static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);

static unsigned int _sign_kID = 1;

static char rx_buf[MSG_SIZE];
static char tx_buf[MSG_SIZE];
static int  rx_buf_pos;

static char *upload_did    = NULL;
static char *upload_diddoc = NULL;

/*
 * Print a null-terminated string character by character to the UART interface
 */
static void _print_uart(char *buf)
{
	int msg_len = strlen(buf);

	for (int i = 0; i < msg_len; i++) {
		uart_poll_out(uart_dev, buf[i]);
	}
}

/*
 * Read characters from UART until line end is detected. Afterwards push the
 * data to the message queue.
 */
static void serial_cb(const struct device *dev, void *user_data)
{
	uint8_t c;

	if (!uart_irq_update(uart_dev)) {
		return;
	}

	if (!uart_irq_rx_ready(uart_dev)) {
		return;
	}

	/* read until FIFO empty */
	while (uart_fifo_read(uart_dev, &c, 1) == 1) {
		if ((c == '\n' || c == '\r') && rx_buf_pos > 0) {
			/* terminate string */
			rx_buf[rx_buf_pos] = '\0';

			/* if queue is full, message is silently dropped */
			k_msgq_put(&uart_msgq, &rx_buf, K_NO_WAIT);

			/* reset the buffer (it was copied to the msgq) */
			rx_buf_pos = 0;
		} else if (rx_buf_pos < (sizeof(rx_buf) - 1)) {
			rx_buf[rx_buf_pos++] = c;
		}
		/* else: characters beyond buffer size are dropped */
	}
}

int iotex_pal_device_register_init(char *deviceDID, char *deviceDIDDoc, unsigned int sign_kID)
{
    if (NULL == deviceDID || NULL == deviceDIDDoc)
        return -1;
    
	if (sign_kID)
        _sign_kID = sign_kID;

	if (!device_is_ready(uart_dev)) {
		printk("UART device not found!");
		return -1;
	}

	/* configure interrupt and callback to receive data */
	int ret = uart_irq_callback_user_data_set(uart_dev, serial_cb, NULL);
	if (ret < 0) {
		if (ret == -ENOTSUP) {
			printk("Interrupt-driven UART API support not enabled\n");
		} else if (ret == -ENOSYS) {
			printk("UART device does not support interrupt-driven API\n");
		} else {
			printk("Error setting UART callback: %d\n", ret);
		}

		return ret;
	}

	uart_irq_rx_enable(uart_dev);

	if (NULL == upload_did)
    	upload_did = iotex_utils_device_register_did_upload_prepare(deviceDID, _sign_kID);

	if (NULL == upload_diddoc)
    	upload_diddoc = iotex_utils_device_register_diddoc_upload_prepare(deviceDIDDoc, _sign_kID);
    
    return 0;
}

int iotex_pal_device_register_loop(void)
{
    if (NULL == upload_did || NULL == upload_diddoc)
        return -1;

    if (0 == _sign_kID)
        return -1;

    while (k_msgq_get(&uart_msgq, &tx_buf, K_MSEC(500)) == 0) {

        if (0 == strcmp("getdid", tx_buf)) {

            _print_uart(upload_did);

        } else if (0 == strcmp("getdiddoc", tx_buf)) {

            _print_uart(upload_diddoc);

        } else if (0 == strncmp("S", tx_buf, 1)) {

            char *sign = iotex_utils_device_register_signature_response_prepare(tx_buf + 1, _sign_kID);
            _print_uart(sign);

        } else if (0 == strcmp("quit", tx_buf)) 
			return 1;

    }

	return 0;  
}



