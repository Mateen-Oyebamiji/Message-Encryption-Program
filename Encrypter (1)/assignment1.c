#include <stdio.h>
#include <string.h>

#define MAX_BUF  256
#define IV 0b11001011


void encode(unsigned char*, unsigned char*, unsigned char);
void decode(unsigned char*, unsigned char*, unsigned char, int);

unsigned char computeKey(unsigned char);
unsigned char encryptByte(unsigned char, unsigned char);
unsigned char decryptByte(unsigned char,unsigned char);
unsigned char getBit(unsigned char, int);
unsigned char setBit(unsigned char, int);
unsigned char clearBit(unsigned char, int);

/*Helper Functions*/
void getKey(unsigned char);
void printChar(unsigned char);
unsigned char cShift(unsigned char, int); 
unsigned char rShift(unsigned char, int);

int main()
{
  char str[8];
  int  choice;

  printf("\nYou may:\n");
  printf("  (1) Encrypt a message \n");
  printf("  (2) Decrypt a message \n");
  printf("\n  what is your selection: ");
  fgets(str, sizeof(str), stdin);
  sscanf(str, "%d", &choice);
  
  /*Declarations*/
  unsigned char key2;
  int key,num,numBytes;
  unsigned char pt[MAX_BUF];
  unsigned char ct[MAX_BUF];
  unsigned char ptemp[MAX_BUF];
  unsigned char ctemp[MAX_BUF];
  

  switch (choice) {

    case 1:
      /* Prompts the user for partial key */ 
      while(1){
        printf("Please enter a number between 1 and 15: ");
        scanf("%d",&key);
        if(key>0 && key<16)
           
          break;
         
        printf("This is not a number between 1 and 15\n");
      } 
  
      key2=key;
      
      /* encrypting plaintext using functions*/
      printf("Enter plaintext: ");
      while(getchar() != '\n');
      fgets(ptemp,sizeof(ptemp), stdin);
      printf("pt: %s",ptemp);
      printf("\n");
      encode(ptemp,ct,key2);
      printf("the ciphertext is:\n");
      
      for(int i=0;i < strlen(ptemp);++i){
        printf("%03d ",ct[i]);
      }
      printf("\n");
      
      

      break;

    case 2:
      
      /* Prompts the user for partial key*/
      while(1){
        printf("Please enter a number between 1 and 15: ");
        scanf("%d",&key);
        if(key>0 && key<16)
           
          break;
 
 
        printf("This is not a number between 1 and 15\n");
      } 
  
      key2=key;
      
      /* decrypting ciphertext using decryting functions */
      printf("Enter ciphertext:");
      
      int i=0;
      while(num != -1){
      scanf("%d",&num);
      ct[i]=num;
      ++i;
      }
      numBytes=i-1;
      decode(ct,pt,key2,numBytes);      
      
      printf("\nplaintext: \n");
      int k=0;
      while(pt[k] != '\0'){
      printf("%c",pt[k]);
      ++k;
      }
      printf("\n");
  

      break;

    default:
      printf("Select either number 1 or 2\n");

      break;
  }

  return 0;
}



/*
  Function:  getBit
  Purpose:   retrieve value of bit at specified position
       in:   character from which a bit will be returned
       in:   position of bit to be returned
   return:   value of bit n in character c (0 or 1)
*/
unsigned char getBit(unsigned char c, int n)   
{ 
  return ((c & (1 << n)) >>n);
}

/*
  Function:  setBit
  Purpose:   set specified bit to 1
       in:   character in which a bit will be set to 1
       in:   position of bit to be set to 1
   return:   new value of character c with bit n set to 1
*/
unsigned char setBit(unsigned char c, int n)   
{ 
  c= c | (1<<n);
  return c;
}

/*
  Function:  clearBit
  Purpose:   set specified bit to 0
       in:   character in which a bit will be set to 0
       in:   position of bit to be set to 0
   return:   new value of character c with bit n set to 0
*/
unsigned char clearBit(unsigned char c, int n) 
{ 
  c = c & (~(1 << n));
  return c;
}

/*
  Function: getKey
  Purpose:  prompt the user for a partial key
       in:  empty unsigned char
       out: a partial key
*/
void getKey(unsigned char key){
  int key2;
  while(1){
    printf("Please enter a number between 1 and 15: ");
    scanf("%d",&key2);
    
    if(key2>0 && key2<16)
      break;
      
    printf("This is not a number between one and 15!\n");
  }
  key=key2;
}

/*
  Function: printChar
  Purpose:  prints the binary of any unsigned char to the screen
       in:  an unsigned char
      out:  the binary form of an unsigned char
*/
void printChar(unsigned char c){
  printf("the full binary is: ");
  for(int i=7;i>-1;i--)
    printf("%d",getBit(c,i));
  printf("\n");
  
}

/*
  Function: computeKey
  Purpose:  computes the key from a partial key
       in:  a partial key
      out:  a computed key, with the mirror and current bit values set
*/
unsigned char computeKey(unsigned char partial){
  int temp,sev;
  unsigned char x,y;
  y=partial;
  for(int i=0;i<4;++i){
    temp=getBit(y,i);
    sev=(7-i);
    if(temp == 1)
      x=setBit(y,sev);
    else
      x=clearBit(y,sev);
    
    y=x;
  } 
  return x;
}

/*
  Function: encode
  Purpose:  encoding a plaintext
       in:  plaintext to be encrypted
       in:  ciphertext array to store encrypted values
       in:  key used for encryption
*/
void encode(unsigned char *pt,unsigned char *ct,unsigned char k){
  ct[0]=0;
  unsigned char src,ciph,key;
  key=computeKey(k);
  ciph=IV;
  int i=0;
  while(pt[i] != '\0'){
  src= pt[i] ^ ciph;
  ciph=encryptByte(src,key);
  ct[i]=ciph;
  
  ++i;
  }
   
}

/*
  Function: cShift
  Purpose:  perform a circular left shift on a given byte
       in:  character to be circular left shifted
       in:  number of bits shifted
   return:  the new byte that has been circular shifted
*/
unsigned char cShift(unsigned char c,int n){
  return ((c << n)|(c >> (8-n)));
}

/*
  Function: encryptByte
  Purpose:  encryption process using the source byte and the key
       in:  the source byte
       in:  the computed key
   return:  the the ciphertext byte
*/
unsigned char encryptByte(unsigned char src,unsigned char k){
  unsigned char temp,ct,xor,y;
  temp=cShift(src,2);
  ct=0;
  for(int i=0;i<8;++i){
    xor=getBit(temp,i) ^ getBit(k,7-i);
    if(xor==1)
      y=setBit(ct,i);
    else
      y=clearBit(ct,i);
    
    ct=y;
  } 
  return y;
     
}


/*
  Function: decryptByte
  Purpose:  decryption process using a ciphertext byte and the key
  in:       the ciphertext byte
  in:       the computed key
  return:   the source byte
*/
unsigned char decryptByte(unsigned char ct,unsigned char k){
  unsigned char src,y,xor;
  src=0;
  for(int i=0;i<8;++i){
    xor=getBit(ct,i) ^ getBit(k,7-i);
    if(xor==1)
      y=setBit(src,i);
    else
      y=clearBit(src,i);
    
    src=y;
  } 
  return rShift(y,2);

}


/*
  Function: rShift
  Purpose:  perform a circular right shift on a byte
       in:  character to be circular right shifted
       in:  number of bits shifted
   return:  the new byte that has been shifted
*/
unsigned char rShift(unsigned char c, int n){
  return((c >> n)|(c<<(8-n)));
}


/*
  Function: decode
  Purpose:  decoding a plaintext
       in:  ciphertext to be decrypted
       in:  plaintext array to store decrypted data
       in:  key used for decryption
       in:  number of Bytes in the ciphertext array 
*/
void decode(unsigned char *ct,unsigned char *pt,unsigned char k,int numBytes){
  unsigned char ciph,p,key,src;
  key=computeKey(k);
  ciph=IV;
  
  for(int i=0;i<numBytes;++i){
    src= decryptByte(ct[i],key);
    p= src ^ ciph;
    pt[i]=p;
    ciph=ct[i];
    
    
  }
  
}
