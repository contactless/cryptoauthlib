/**
 * \file
 * \brief ATCA Hardware abstraction layer for Linux using I2C.
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */

#include "atca_hal.h"
#include "hal_linux_i2c_userspace.h"
#include "atca_device.h"

#include <linux/i2c-dev.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>

typedef struct 
{
    ATCADeviceType devtype;
    uint8_t pattern[4];
} ATCADeviceSignature;

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

// File scope globals
ATCAI2CMaster_t *i2c_hal_data[MAX_I2C_BUSES]; // map logical, 0-based bus number to index
int i2c_bus_ref_ct = 0;                       // total in-use count across buses

/** \brief discover i2c buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application
 * of the a-priori knowledge.This function is not implemented.
 * \param[in] i2c_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{
    DIR *dir = opendir("/dev");
    struct dirent *ent;
    int found = 0;

    if (dir == NULL)
    {
        return ATCA_GEN_FAIL;
    }

    while ((found < max_buses) && ((ent = readdir(dir)) != NULL))
    {
        if (memcmp(ent->d_name, "i2c-", 4) != 0)
        {
            continue;
        }
        i2c_buses[found] = atoi(ent->d_name+4);
        ++found;
    }
    closedir(dir);
    return ATCA_SUCCESS;
}


ATCA_STATUS linux_i2c_probe_device(ATCAIfaceCfg *cfg, ATCADevice device)
{
    ATCAIface discoverIface;
    ATCACommand command;
    ATCAPacket packet;
    ATCA_STATUS status;

    const ATCADeviceSignature signatures[] = {
        { ATECC608A, { 0x00, 0x00, 0x60, 0x01 } },
        { ATECC608A, { 0x00, 0x00, 0x60, 0x02 } },
        { ATECC508A, { 0x00, 0x00, 0x50, 0x00 } },
        { ATECC108A, { 0x80, 0x00, 0x10, 0x01 } },
        { ATSHA204A, { 0x00, 0x02, 0x00, 0x08 } },
        { ATSHA204A, { 0x00, 0x02, 0x00, 0x09 } },
        { ATSHA204A, { 0x00, 0x04, 0x05, 0x00 } }
    };

    discoverIface = atGetIFace(device);
    command = atGetCommands(device);

    // wake up device
    // If it wakes, send it a dev rev command.  Based on that response, determine the device type
    // BTW - this will wake every cryptoauth device living on the same bus (ecc508a, sha204a)

    if (hal_i2c_wake(discoverIface) == ATCA_SUCCESS)
    {
        memset(&packet, 0x00, sizeof(packet));

        // get devrev info and set device type accordingly
        atInfo(command, &packet);

        if ( (status = atGetExecTime(packet.opcode, command)) != ATCA_SUCCESS)
        {
            return status;
        }

        // send the command
        if ( (status = atsend(discoverIface, (uint8_t*)&packet, packet.txsize)) != ATCA_SUCCESS)
        {
            return status;
        }

        // delay the appropriate amount of time for command to execute
        atca_delay_ms((command->execution_time_msec) + 1);

        // receive the response
        if ( (status = atreceive(discoverIface, &(packet.data[0]), &(packet.rxsize) )) != ATCA_SUCCESS)
        {
            return status;
        }

        if ( (status = isATCAError(packet.data)) != ATCA_SUCCESS)
        {
            return status;
        }

        cfg->devtype = ATCA_DEV_UNKNOWN;

        // determine device type from common info and dev rev response byte strings
        for (int i = 0; i < (int)sizeof(signatures) / sizeof(ATCADeviceSignature); i++)
        {
            if (memcmp(&packet.data[1], &signatures[i].pattern, sizeof(signatures[i].pattern)) == 0)
            {
                cfg->devtype = signatures[i].devtype;
                return ATCA_SUCCESS;
            }
        }
    }
    return ATCA_GEN_FAIL;
}

/** \brief try to find CryptoAuth device type
 * \param[in,out] cfg - pointer to interface config structure with assigned bus number and slave address.
 *                      Upon success the function sets devtype value of the structure.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_discover_device_type(ATCAIfaceCfg *cfg)
{
    ATCADevice device;
    ATCA_STATUS status;

    /** \brief default configuration, to be reused during discovery process */
    ATCAIfaceCfg discoverCfg = {
        .iface_type             = ATCA_I2C_IFACE,
        .devtype                = ATECC608A, // Use ATECC608A as it has longest execution time of INFO command
        .atcai2c.slave_address  = cfg->atcai2c.slave_address,
        .atcai2c.bus            = cfg->atcai2c.bus,
        .atcai2c.baud           = cfg->atcai2c.baud,
        .wake_delay             = 800,
        .rx_retries             = 3
    };

    ATCAHAL_t hal;
    memset(&hal, 0, sizeof(hal));
    hal_i2c_init(&hal, &discoverCfg);
    device = newATCADevice(&discoverCfg);
    status = linux_i2c_probe_device(cfg, device);
    deleteATCADevice(&device);
    hal_i2c_release(hal.hal_data);
    return status;
}

/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in]  busNum  logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg     pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] found   number of devices found on this bus
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_discover_devices(int busNum, ATCAIfaceCfg cfg[], int *found)
{
    ATCAIfaceCfg *head = cfg;
    ATCADevice device;
    ATCAIface discoverIface;

    /** \brief default configuration, to be reused during discovery process */
    ATCAIfaceCfg discoverCfg = {
        .iface_type             = ATCA_I2C_IFACE,
        .devtype                = ATECC608A, // Use ATECC608A as it has longest execution time of INFO command
        .atcai2c.slave_address  = 0x08,
        .atcai2c.bus            = busNum,
        .atcai2c.baud           = 400000,
        //.atcai2c.baud = 100000,
        .wake_delay             = 800,
        .rx_retries             = 3
    };

    ATCAHAL_t hal;
    memset(&hal, 0, sizeof(hal));
    hal_i2c_init(&hal, &discoverCfg);
    device = newATCADevice(&discoverCfg);
    discoverIface = atGetIFace(device);

    // iterate through all addresses on given i2c bus
    // all valid 7-bit addresses go from 0x08 to 0x77
    for (uint8_t slaveAddress = 0x08; slaveAddress <= 0x77; slaveAddress++)
    {
        discoverCfg.atcai2c.slave_address = slaveAddress << 1;  // turn it into an 8-bit address which is what the rest of the i2c HAL is expecting when a packet is sent
        if (linux_i2c_probe_device(&discoverCfg, device) == ATCA_SUCCESS) {
            memcpy( (uint8_t*)head, (uint8_t*)&discoverCfg, sizeof(ATCAIfaceCfg));
            atca_delay_ms(15);
            head++;
            (*found)++;
        }
        hal_i2c_idle(discoverIface);
    }
    deleteATCADevice(&device);
    hal_i2c_release(hal.hal_data);
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C init
 *
 * this implementation assumes I2C peripheral has been enabled by user. It only initialize an
 * I2C interface using given config.
 *
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_init(void* hal, ATCAIfaceCfg* cfg)
{
    int bus = cfg->atcai2c.bus; // 0-based logical bus number
    ATCAHAL_t *phal = (ATCAHAL_t*)hal;
    uint8_t i;

    if (i2c_bus_ref_ct == 0)    // power up state, no i2c buses will have been used
    {
        for (i = 0; i < MAX_I2C_BUSES; i++)
        {
            i2c_hal_data[i] = NULL;
        }
    }

    i2c_bus_ref_ct++;       // total across buses

    if (bus >= 0 && bus < MAX_I2C_BUSES)
    {
        // if this is the first time this bus and interface has been created, do the physical work of enabling it
        if (i2c_hal_data[bus] == NULL)
        {
            i2c_hal_data[bus] = malloc(sizeof(ATCAI2CMaster_t) );
            i2c_hal_data[bus]->ref_ct = 1;  // buses are shared, this is the first instance

            snprintf(i2c_hal_data[bus]->i2c_file, sizeof(i2c_hal_data[bus]->i2c_file), "/dev/i2c-%d", bus);

            // store this for use during the release phase
            i2c_hal_data[bus]->bus_index = bus;
        }
        else
        {
            // otherwise, another interface already initialized the bus, so this interface will share it and any different
            // cfg parameters will be ignored...first one to initialize this sets the configuration
            i2c_hal_data[bus]->ref_ct++;
        }

        phal->hal_data = i2c_hal_data[bus];

        return ATCA_SUCCESS;
    }
    return ATCA_COMM_FAIL;
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send
 * \param[in] iface     instance
 * \param[in] txdata    pointer to space to bytes to send
 * \param[in] txlength  number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    int f_i2c;  // I2C file descriptor

    // for this implementation of I2C with CryptoAuth chips, txdata is assumed to have ATCAPacket format

    // other device types that don't require i/o tokens on the front end of a command need a different hal_i2c_send and wire it up instead of this one
    // this covers devices such as ATSHA204A and ATECCx08A that require a word address value pre-pended to the packet
    // txdata[0] is using _reserved byte of the ATCAPacket
    txdata[0] = 0x03; // insert the Word Address Value, Command token
    txlength++;       // account for word address value byte.

    // Initiate I2C communication
    if ( (f_i2c = open(i2c_hal_data[bus]->i2c_file, O_RDWR)) < 0)
    {
        return ATCA_COMM_FAIL;
    }

    // Set Slave Address
    if (ioctl(f_i2c, I2C_SLAVE, cfg->atcai2c.slave_address >> 1) < 0)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    // Send data
    if (write(f_i2c, txdata, txlength) != txlength)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    close(f_i2c);
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C receive function
 * \param[in] iface     instance
 * \param[in] rxdata    pointer to space to receive the data
 * \param[in] rxlength  ptr to expected number of receive bytes to request
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    int f_i2c;  // I2C file descriptor

    // Initiate I2C communication
    if ( (f_i2c = open(i2c_hal_data[bus]->i2c_file, O_RDWR)) < 0)
    {
        return ATCA_COMM_FAIL;
    }

    // Set Slave Address
    if (ioctl(f_i2c, I2C_SLAVE, cfg->atcai2c.slave_address >> 1) < 0)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    // Receive data
    if (read(f_i2c, rxdata, *rxlength) != *rxlength)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    close(f_i2c);
    return ATCA_SUCCESS;
}

/** \brief method to change the bus speed of I2C.This function is not used in Linux.
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */

void change_i2c_speed(ATCAIface iface, uint32_t speed)
{

}

/** \brief wake up CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    int f_i2c;  // I2C file descriptor
    uint8_t data[4], expected[4] = { 0x04, 0x11, 0x33, 0x43 };
    uint8_t dummy_byte = 0x00;

    // Initiate I2C communication
    if ( (f_i2c = open(i2c_hal_data[bus]->i2c_file, O_RDWR)) < 0)
    {
        return ATCA_COMM_FAIL;
    }

    // Send the wake by writing to an address of 0x00
    // Create wake up pulse by sending a slave address 0f 0x00.
    // This slave address is sent to device by using a dummy write command.
    if (ioctl(f_i2c, I2C_SLAVE, 0x00) < 0)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    // Dummy Write
    if (write(f_i2c, &dummy_byte, 1) < 0)
    {
        // This command will always return NACK.
        // So, the return code is being ignored.
    }

    atca_delay_us(cfg->wake_delay); // wait tWHI + tWLO which is configured based on device type and configuration structure

    // Set Slave Address
    if (ioctl(f_i2c, I2C_SLAVE, cfg->atcai2c.slave_address >> 1) < 0)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    // Receive data
    if (read(f_i2c, data, 4) != 4)
    {
        close(f_i2c);
        return ATCA_RX_NO_RESPONSE;
    }

    close(f_i2c);
    // if necessary, revert baud rate to what came in.

    if (memcmp(data, expected, 4) == 0)
    {
        return ATCA_SUCCESS;
    }
    return ATCA_COMM_FAIL;
}

/** \brief idle CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to idle
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    uint8_t data = 0x02; // idle word address value
    int f_i2c;           // I2C file descriptor

    // Initiate I2C communication
    if ( (f_i2c = open(i2c_hal_data[bus]->i2c_file, O_RDWR) ) < 0)
    {
        return ATCA_COMM_FAIL;
    }

    // Set Slave Address
    if (ioctl(f_i2c, I2C_SLAVE, cfg->atcai2c.slave_address >> 1) < 0)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    // Send data
    if (write(f_i2c, &data, 1) != 1)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    close(f_i2c);
    return ATCA_SUCCESS;
}

/** \brief sleep CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to sleep
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    uint8_t data = 0x01; // sleep word address value
    int f_i2c;           // I2C file descriptor

    // Initiate I2C communication
    if ( (f_i2c = open(i2c_hal_data[bus]->i2c_file, O_RDWR)) < 0)
    {
        return ATCA_COMM_FAIL;
    }

    // Set Slave Address
    if (ioctl(f_i2c, I2C_SLAVE, cfg->atcai2c.slave_address >> 1) < 0)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    // Send data
    if (write(f_i2c, &data, 1) != 1)
    {
        close(f_i2c);
        return ATCA_COMM_FAIL;
    }

    close(f_i2c);
    return ATCA_SUCCESS;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t*)hal_data;
    int bus;

    i2c_bus_ref_ct--;   // track total i2c bus interface instances for consistency checking and debugging

    // if the use count for this bus has gone to 0 references, disable it.  protect against an unbracketed release
    if (hal && --(hal->ref_ct) <= 0 && i2c_hal_data[hal->bus_index] != NULL)
    {
        bus = hal->bus_index;
        free(i2c_hal_data[bus]);
        i2c_hal_data[bus] = NULL;
    }

    return ATCA_SUCCESS;
}

/** @} */
