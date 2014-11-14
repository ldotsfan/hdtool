/***************************************************************************
        hdtool.c - HDD security manipulation tool with Xbox support    
                             -------------------
    begin                : Mon May 31st 00:33:22 GMT 2004
    copyright            : (C) 2004 David Pye
    email                : dmp@davidmpye.dyndns.org
    Id:			 : $Id: hdtool.c,v 1.7 2004/08/09 20:08:15 davidmpye Exp $
 ***************************************************************************/

 /***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

/*  Credits:
 *
 *  Much of the initial code came from the xbox_tool code written by Ed
 *  Hucek, and the crypto code comes from Cromwell's source/xbox_tool 
 *  also.
 *
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <getopt.h>
#include "consts.h"

#ifdef Xbox 
#include "i2c-dev.h"
#include "BootEEPROM.h"
#include "BootHddKey.h"
#include "rc4.h"
#include "sha1.h"
#endif
void showUsage(char *progname);
void showDriveInfo(char *ide_data);
int changeDriveSecurity(char *device, unsigned char ide_cmd, char *password);
void print_hex(unsigned char *szString,long len);
int hdd_ident(char *device,unsigned char *buffer);
static int security_master =1;

int main(int argc, char **argv) {
	char *password=0l;
	char *device=0l;
	int c;
#ifdef Xbox
	int pw_from_eeprom=0;
	char *eeprom_file=0l;
	EEPROMDATA eeprom;  
#endif
	unsigned char ide_cmd=0;
	unsigned char ide_password[32];

        unsigned char serial[0x14];
	unsigned char model[0x28];
	unsigned char s_length = 0x14;
	unsigned char m_length = 0x28;
	unsigned char  ide_device_identity[512]; //response from DEVICE_IDENTIFY
	unsigned char *HDSerial = &ide_device_identity[HDD_SERIAL_OFFSET];
	unsigned char *HDModel  = &ide_device_identity[HDD_MODEL_OFFSET];
	unsigned char HDDPass[256];
	memset(ide_password,0x00,32);
	
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"operation",0,0,'o'},
			{"password",1,0,'p'},
#ifdef Xbox
			{"autogen-pw",0,0,'a'},
			{"eeprom-file",1,0,'e'},
#endif
			{0, 0, 0, 0}
		};		
		c = getopt_long (argc, argv, "e:o:p:a", long_options, &option_index);
		if (c == -1) break;

		switch (c) {
			case 'p':
				password = malloc(strlen(optarg));
				strncpy(password, optarg, strlen(optarg));
				break;
#ifdef Xbox
			case 'a':
				pw_from_eeprom=1;
				break;
			case 'e':
				eeprom_file=malloc(strlen(optarg));
				strncpy(eeprom_file, optarg, strlen(optarg));
				break;
#endif
			case 'o':
				if (!strcmp(optarg,"LOCK") || !strcmp(optarg,"lock")) 
					ide_cmd = WIN_SECURITY_SET_PASS;
				else if(!strcmp(optarg,"UNLOCK") || !strcmp(optarg,"unlock"))
					ide_cmd = WIN_SECURITY_UNLOCK;
				else if (!strcmp(optarg,"DISABLE-PW") || !strcmp(optarg,"disable-pw"))
					ide_cmd = WIN_SECURITY_DISABLE;
				else showUsage(argv[0]);
		}
	}

	if (optind!=0) {
		device = argv[optind];
	}
	
	if (device==0l) showUsage(argv[0]);
	
	if (ide_cmd) {
		//If an ide command was specified, there must be a password.
#ifndef Xbox
		if (password==0l) showUsage(argv[0]);
#else
		if (password==0l && (!pw_from_eeprom && !eeprom_file)) showUsage(argv[0]);
		if (eeprom_file!=0l && (pw_from_eeprom || password!=0l)) showUsage(argv[0]);
		if (password!=0l && pw_from_eeprom) showUsage(argv[0]);
#endif
	}
     	if((hdd_ident(device,ide_device_identity) != 0)) exit(0);
       	memset(serial,0,0x15);
      	memset(model,0,0x29);
        memset(HDDPass,0,256);
     	s_length = copy_swap_trim(serial,HDSerial,s_length);
    	m_length = copy_swap_trim(model,HDModel,m_length);
	printf("HDD Serial      : %.*s\n",s_length,serial);
       	printf("HDD Model       : %.*s\n",m_length,model);
    
#ifdef Xbox
	if (pw_from_eeprom) {
		int i2cdev;
		int i;	
		BYTE *pb=(BYTE *)&eeprom;
		i2cdev = open("/dev/i2c-0",O_RDWR);
		if (i2cdev<=0) i2cdev = open("/dev/i2c/0", O_RDWR);
		if (i2cdev<=0) {
			printf("Unable to open either /dev/i2c/0 or /dev/i2c-0\n");
			exit(1);
		}
		
		if (ioctl(i2cdev,I2C_SLAVE_FORCE,0x54) < 0) {
			fprintf(stderr,"Error: Could not set address to %d: %s\n",0x54, strerror(errno));
			return 1;
		}
			            
		for( i = 0; i < 256; i++ ) {
			*pb++ = i2c_smbus_read_byte_data(i2cdev,i);
		}
		close(i2cdev);
	}
	else if (eeprom_file!=0l) {
          	int fp = open(eeprom_file,O_RDONLY);
	    	if (fp<=0) {
			printf("Error - unable to open file %s\n",eeprom_file);
			exit(1);
		}
		read(fp,&eeprom,sizeof(EEPROMDATA));
		close(fp);
	}
	
	if (pw_from_eeprom || eeprom_file!=0l) {
		BootDecryptEEPROM(&eeprom);
		HMAC_SHA1 (HDDPass, eeprom.HDDKkey, 0x10, model, m_length, serial, s_length);
		printf("HDD password from EEPROM is: ");
		memcpy(ide_password, HDDPass, 20);
   		print_hex(ide_password,32);
		printf("\n");
	}
#endif
	if (password!=0l) {
		//Turn the cmdline-given password into a byte array.
		int i;
		if (strlen(password)%2!=0 || strlen(password)>64) {
			printf("Error, invalid password - must be less than 32 bytes (64 chars)\n");
			printf("and should be an even number of chars\n");
			exit(0);

		}
		for (i=0; i<strlen(password)/2; ++i) {
			char ch[2];
			ch[0] = password[2*i];
			ch[1] = password[2*i+1];

			
			if ( !((ch[0]>='0' && ch[0]<='9') || (ch[0]>='a' && ch[0]<='f') || (ch[0]>='A' && ch[0]<='F')) || 
			(!((ch[1]>='0' && ch[1]<='9') || (ch[1]>='a' && ch[1]<='f') || (ch[1]>='A' && ch[1]<='F')))) { 
				printf("Error - invalid character in password - must be ");
				printf("between 0-9, and a-f\n");
				exit(0);
			}
			ide_password[i] = strtoul(ch,0l,16);
		}
		printf("Using HDD password: ");
		print_hex(ide_password,32);
		printf("\n");
	}

	if (!ide_cmd) {
		//Just display information and exit - no command specified.
		showDriveInfo(ide_device_identity);
		exit(0);
	}
	//Check current drive state
	//Is drive locked now?
	switch (ide_cmd) {
		case WIN_SECURITY_SET_PASS:
			if (!(ide_device_identity[HDD_SECURITY_STATUS_OFFSET]&0x01)) {
				printf("Error - this drive does not support the ATA security spec\n");
				exit(1);
			}
			if ((ide_device_identity[HDD_SECURITY_STATUS_OFFSET]>>1)&0x01) {
				printf("Error - this drive has security set - disable first with -o DISABLE-PW\n");
				exit(1);
			}
			if ((ide_device_identity[HDD_SECURITY_STATUS_OFFSET]>>2)&0x01) {
				printf("Error - drive is locked -unlock first, before disabling\n");
				exit(1);
			}
			break;
		case WIN_SECURITY_UNLOCK:
			if (!((ide_device_identity[HDD_SECURITY_STATUS_OFFSET]>>2)&0x01)) {
				printf("Error - drive is not locked\n");
				exit(1);
			}
			break;
		case WIN_SECURITY_DISABLE:
			if ((ide_device_identity[HDD_SECURITY_STATUS_OFFSET]>>2)&0x01) {
				printf("Error - drive is locked -unlock first, before disabling\n");
				exit(1);
		}
			if (!(ide_device_identity[HDD_SECURITY_STATUS_OFFSET]&0x02)) {
				printf("Error - drive has no security set\n"); 
				exit(1);
			}
			break;
	}

	if (ide_cmd == WIN_SECURITY_SET_PASS) {
		struct request { 
			ide_task_request_t req; 
			char out[512]; 
		} request;	
		ide_task_request_t *reqtask=&request.req;
		task_struct_t *taskfile=(task_struct_t *) reqtask->io_ports;
		int dev = open(device,O_RDWR);
		memset(&request, 0, sizeof(request));
		taskfile->command = ide_cmd;
	
		reqtask->data_phase = TASKFILE_OUT;
		reqtask->req_cmd = IDE_DRIVE_TASK_OUT;
		reqtask->out_size = 512;

		//Copy the password into the data section
                request.out[0] = security_master & 0x01;
		memcpy(&request.out[2],"XBOXSCENE",32);
		if(ioctl(dev,HDIO_DRIVE_TASKFILE,&request)) {
			close(dev);
			return 0;
		}
		close(dev);		

	}
	
	if (changeDriveSecurity(device, ide_cmd, ide_password)) {
		printf("Command completed successfully\n");
	}

	return 0;
}

void showUsage(char *progname) {
	printf("%s (c) David Pye dmp@davidmpye.dyndns.org\n",progname);
	printf("Licenced under the GNU GPL\n");
	printf("Usage:  %s <options> <device>\n\n", progname);
	printf("-p, --password <password> - the password to use.\n");
#ifdef Xbox
	printf("-e  --eeprom-file <file>  - use an Xbox eeprom image from file to generate password\n");
	printf("-a, --autogen-pw          - the password will be generated from the xbox motherboard.\n");
#endif
	printf("-o, --operation           - the operation to perform, either LOCK, UNLOCK, or DISABLE-PW.\n\n");
	printf("Either -a, -e or -p  must be specified. -d is mandatory\n");
	printf("If no operation is specified, the current drive security settings will be displayed\n");
	printf("Example,in an xbox:\n %s  --autogen-pw --operation DISABLE-PW /dev/hda",progname);
	printf("\nwill permanently remove the HDD password protection\n");
	exit(0);
}

void showDriveInfo(char *ide_device_identity) {
	printf("Drive Security Settings\n");
	printf("Security supported : %s\n", (ide_device_identity[HDD_SECURITY_STATUS_OFFSET]&0x01)?"yes":"no");
	printf("Security enabled : %s\n", (ide_device_identity[HDD_SECURITY_STATUS_OFFSET]&0x02)?"yes":"no");
	printf("Security locked : %s\n", (ide_device_identity[HDD_SECURITY_STATUS_OFFSET]&0x04)?"yes":"no");
	printf("Security frozen : %s\n", (ide_device_identity[HDD_SECURITY_STATUS_OFFSET]&0x08)?"yes":"no");
	printf("Security count expired: %s\n", (ide_device_identity[HDD_SECURITY_STATUS_OFFSET]&0x10)?"yes":"no");
}

int hdd_ident(char *device,unsigned char *buffer) {
	unsigned char args[4+512] = { WIN_IDENTIFY, 0, 0, 1, };
	unsigned char *data = &args[4];
	int rc;
	int dev = open(device,O_RDONLY);
	if (dev <= 0) {
		printf("Unable to open device %s\n",device);
		exit(-1);
	}
	
	memset(data,0,512);
	rc = ioctl(dev,HDIO_DRIVE_CMD,args);
	if(rc != 0) {
		printf("HDIO_DRIVE_CMD(identify) failed - is drive frozen?\n");
	}
     	close(dev);
     	memcpy(buffer,data,512);
   	return rc;
}



int changeDriveSecurity(char *device, unsigned char ide_cmd, char *password) {
	struct request { 
		ide_task_request_t req; 
		char out[512]; 
	} request;	
	ide_task_request_t *reqtask=&request.req;
	task_struct_t *taskfile=(task_struct_t *) reqtask->io_ports;
        int dev = open(device,O_RDWR);
	memset(&request, 0, sizeof(request));
	taskfile->command = ide_cmd;
	
	reqtask->data_phase = TASKFILE_OUT;
	reqtask->req_cmd = IDE_DRIVE_TASK_OUT;
	reqtask->out_size = 512;

	//Copy the password into the data section
	memcpy(&request.out[2],password,32);
	if(ioctl(dev,HDIO_DRIVE_TASKFILE,&request)) {
		close(dev);
	        return 0;
        }
	close(dev);
        return 1;
}

void print_hex(unsigned char *szString,long len) {
	int i;
	for(i=0;i<len;i++) {
		printf("%02x",szString[i]);
	}
}
