#include <math.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <byteswap.h>
#define ROUNDS 7

#define CHUNK_START 0x01
#define CHUNK_END 0x02
#define PARENT 0x04
#define ROOT 0x08
#define KEYED_HASH 0x10
#define DERIVE_KEY_CONTEXT 0x20
#define DERIVE_KEY_MATERIAL 0x40

uint32_t IV[8] = {
      0x6a09e667,
      0xbb67ae85,
      0x3c6ef372,
      0xa54ff53a,
      0x510e527f,
      0x9b05688c,
      0x1f83d9ab,
      0x5be0cd19,
};

uint32_t FLAGS = 0;

typedef struct bblock{
    uint32_t m[16];
    /* uint32_t t[2]; */
    uint32_t flags,len;
} bblock;

typedef struct bchunk{
    bblock blocks[16];
    uint32_t size,
             flags,
             blk_num,
             complete,
             isRoot,
             last_blk_len,
             t[2],
             hash[8];
    uint64_t index;
} bchunk;

typedef struct Stack {
    int top;
    unsigned capacity;
    bchunk* array;
} Stack;

Stack* createStack(unsigned capacity){
    Stack* stack = (Stack*)malloc(sizeof(Stack));
    stack->capacity = capacity;
    stack->top = -1;
    stack->array = (bchunk*)malloc(stack->capacity * sizeof(bchunk));
    return stack;
}

int isFull(Stack* stack){
    return stack->top == stack->capacity - 1;
}

int isEmpty(Stack* stack){
    return stack->top == -1;
}

void push(Stack* stack, bchunk item){
    if (isFull(stack))
        return;
    stack->array[++stack->top] = item;
}

bchunk pop(Stack* stack){
    return stack->array[stack->top--];
}

bchunk peek(Stack* stack){
    return stack->array[stack->top];
}


void permute(uint32_t m[16]){
    uint32_t m_temp[16];
    for (int i = 0; i < 16; i++){
        m_temp[i] = m[i];
    }
    m[0]=m_temp[2]; 
    m[1]=m_temp[6]; 
    m[2]=m_temp[3]; 
    m[3]=m_temp[10]; 
    m[4]=m_temp[7]; 
    m[5]=m_temp[0]; 
    m[6]=m_temp[4]; 
    m[7]=m_temp[13]; 
    m[8]=m_temp[1]; 
    m[9]=m_temp[11]; 
    m[10]=m_temp[12]; 
    m[11]=m_temp[5]; 
    m[12]=m_temp[9]; 
    m[13]=m_temp[14]; 
    m[14]=m_temp[15]; 
    m[15]=m_temp[8]; 
}


uint32_t rotate(uint32_t x, uint32_t n){
    return (x>>n) ^ (x<< (32-n) ); // | ?
}


void G(uint32_t v[16], int a, int b, int c, int d, uint64_t x, uint64_t y){
    uint64_t two32 = ((uint64_t) 1) << 32;    
    // printf("startg-----------------\n");
    v[a] = (v[a] + v[b] + x) % two32;
    // printf("%u\n", v[a]);
    v[d] = rotate((v[d] ^ v[a]),16);
    // printf("%u\n", v[d]);
    v[c] = (v[c] + v[d]) % two32;
    // printf("%u\n", v[c]);
    v[b] = rotate((v[b] ^ v[c]),12);
    // printf("%u\n", v[b]);
    v[a] = (v[a] + v[b] + y) % two32;
    // printf("%u\n", v[a]);
    v[d] = rotate((v[d] ^ v[a]),8);
    // printf("%u\n", v[d]);
    v[c] = (v[c] + v[d]) % two32;
    // printf("%u\n", v[c]);
    v[b] = rotate((v[b] ^ v[c]), 7);
    // printf("%u\n", v[b]);
    // printf("endg-----------------\n");
}


void compress(uint32_t v[16], uint32_t *h, uint32_t m[16], uint32_t t[2], int len, uint32_t flags){
    // init v
    for (int i = 0; i < 8; i++){ // First half from state.
        v[i]=h[i];
    }
    for (int i = 8; i < 12; i++){ // Second half from IV
        v[i]=IV[i-8];
    }

    v[12] =  t[0];                 // Low word of the counter.
    v[13] =  t[1];                 // High word of the counter.
    v[14] =  len;                  // Application data length.
    v[15] =  flags;                // Flags.

    for (int i = 0; i < ROUNDS; i++){
        G(v, 0, 4,  8, 12, m[ 0], m[ 1]);
        G(v, 1, 5,  9, 13, m[ 2], m[ 3]);
        G(v, 2, 6, 10, 14, m[ 4], m[ 5]);
        G(v, 3, 7, 11, 15, m[ 6], m[ 7]);
                                             
        G(v, 0, 5, 10, 15, m[ 8], m[ 9]);
        G(v, 1, 6, 11, 12, m[10], m[11]);
        G(v, 2, 7,  8, 13, m[12], m[13]);
        G(v, 3, 4,  9, 14, m[14], m[15]);

        if (i != ROUNDS-1) permute(m); // possibly not needed for last round
        // permute(m);

    }

    for (int i = 0; i < 8; i++){
        v[i] = v[i] ^ v[i + 8];
        v[i + 8] = v[i + 8] ^ h[i];
    }
    // // printf("compress_out: 0x");
    // for (int i = 0; i < 16; i++){
    //     printf("%x ", v[i]);
    // }
    // printf("\n");

    /* return v; */
}


void process_chunk(bchunk *chunk, uint32_t *h){
    uint32_t v[16], len, flags;
    for (int i = 0; i < 8; i++)
        h[i] = IV[i];
    
    len = 64;

    for (uint64_t i = 0; i < chunk->blk_num; i++){
        // v is truncated to first 8 words
        // printf("block%d--------------------------\n", i);
        bblock blk = chunk->blocks[i];
        blk.flags = chunk->flags;
        if (i != 0) 
            for (int j = 0; j < 8; j++) h[j] = v[j];
        else
            blk.flags += CHUNK_START;
            // flag

        if (i == chunk->blk_num-1) {
            // if (!chunk->complete)  HERE
            len = chunk->size - ( i * 64);
            blk.flags += CHUNK_END;
            // last compression must set ROOT
            if (chunk->isRoot) blk.flags += ROOT;
        }

        blk.len=len;

        compress(v, h, blk.m, chunk->t, blk.len, blk.flags);
        for (int j = 0; j < 8; j++){
            h[j] = v[j];
        }

        // printf("blockend%d--------------------------\n", i);
    }

    for (int j = 0; j < 8; j++)
        h[j] = v[j];

    /* return h; */
}


void parent_cv(uint32_t h[8], uint32_t lhash[8], uint32_t rhash[8], uint32_t flags){
    uint32_t message[16],v[16];
    uint32_t t[2] = {0, 0};
    for (int i = 0; i < 8; i++) h[i] = IV[i];

    // for (int i = 0; i < 8; i++) message[i] = lhash[i]; 
    // for (int i = 8; i < 16; i++) message[i] = rhash[i-8]; 
    // printf("--------------------\n");
    // for (int i = 0; i < 16; i++) printf("%#x ", message[i]);
    // printf("--------------------\n");

    // set mode flags
    flags+=PARENT;
    //process_chunk()
    compress(v, h, message, t, 64, flags);
     
    for (int i = 0; i < 8; i++) h[i] = v[i];
    // return h[0..7]

}

uint32_t count_one(uint32_t x){
    x = (x & (0x55555555)) + ((x >> 1) & (0x55555555));
    x = (x & (0x33333333)) + ((x >> 2) & (0x33333333));
    x = (x & (0x0f0f0f0f)) + ((x >> 4) & (0x0f0f0f0f));
    x = (x & (0x00ff00ff)) + ((x >> 8) & (0x00ff00ff));
    x = (x & (0x0000ffff)) + ((x >> 16) & (0x0000ffff));
    return x;
}

void process_BT(bchunk* msg, uint32_t chunk_num){

    Stack *stack = createStack(chunk_num+1);
    uint32_t child_num=0, parent_num=0, chunks_left;
    uint32_t h[8] = {0};
    uint32_t t[2] = {0,0};

    int i =0;
    while(i < chunk_num){
        push(stack, msg[i]);
        child_num++;

        if (child_num == 2||parent_num==2){
            bchunk cr = pop(stack);
            bchunk cl = pop(stack);
            // printf("--------------------\n");
            // for (int i = 0; i < 8; i++) printf("%#x ", cl.hash[i]);
            // printf("--------------------\n");

            // printf("--------------------\n");
            // for (int i = 0; i < 8; i++) printf("%#x ", cr.hash[i]);
            // printf("--------------------\n");
            uint32_t flag = FLAGS;
            if (i==chunk_num-1 && isEmpty(stack)) flag+=ROOT;
            parent_cv(h, cl.hash, cr.hash, flag);

            bchunk p; // pseudo parent chunk
            for (int i = 0; i < 8; i++) p.hash[i] = h[i];
            push(stack, p);

            if(child_num==2){
                parent_num++;
                child_num-=2;
            }
            if(parent_num==2){
                parent_num--;
            }
        }

        i++;
    }

    // now for the root;
    chunks_left=count_one(chunk_num);
    uint32_t flag = FLAGS;
    uint32_t final[16];

    while (chunks_left){
        if (chunk_num!=1){
            if (chunks_left == 1) break;
            if (chunks_left == 2) flag+=ROOT;
            bchunk cl = pop(stack);
            bchunk cr = pop(stack);
            parent_cv(h, cl.hash, cr.hash, flag);

            bchunk p; // pseudo parent chunk
            for (int i = 0; i < 8; i++){
                p.hash[i] = h[i];
            }
            push(stack, p);
            chunks_left-=2;
        }
        chunks_left--;
    }

    for (int i = 0; i < 8; i++){
        final[i] = h[i];
        printf("%x ", __bswap_32(final[i]));
        /* __bswap_32(h[i]); */
    }

    /* return final[0..7] */

}

bchunk read_chunk(uint64_t len_bytes, uint64_t index, uint64_t chunk_num){
    uint64_t len_words;

    // GET LEN BYTES TRUGH TOTAL input

    // scanf("%lu", &len_bytes);

    // len_bytes = 1;
    // padding na string de entrada
    len_words = len_bytes/4 + (len_bytes%4!=0);
    uint32_t message[len_words];
    // size_t in_size = 4096;
    // char input[] = "a";
    // scanf("%s", input);
    // for (int i = 0; i < 4048;i++){
    //     if (i%4) read(0, message, len_bytes)
    // }

    read(0, message, len_bytes);// words are read in litlle endian format
    // getline(&input,&in_sz,stdin);
    // for (int i = 0, j = 3; i  < in_size; i++ ){
    //     if (j < 0) j = i+3; 
    //     message[j] = input[i];
    //     j--;
    // }

    int rem = len_bytes%4;
    uint32_t mask = 0xFFFFFFFF;
    if (rem!=0){
        mask = mask >> 8*(4-rem);
        message[len_words-1] &= mask;
    }

    bchunk chunk; 
    chunk.index = index;
    chunk.t[0] = (chunk.index)&0xFFFFFFFF;
    chunk.t[1] = (chunk.index>>32)&0xFFFFFFFF;
    chunk.size = len_bytes;
    chunk.flags = 0;
    // chunk.flags+=KEYED_HASH;

    if (chunk_num==1) chunk.isRoot;
    else chunk.isRoot = 0;

    chunk.blk_num = chunk.size / 64 + (chunk.size%64 != 0);
    chunk.last_blk_len = chunk.size - (( chunk.blk_num - 1) * 64);
    chunk.complete = (chunk.last_blk_len == 64);

    uint32_t last_index = 16*(chunk.blk_num-1)+ chunk.last_blk_len/4+ (chunk.last_blk_len%4!=0);
    for (int j = 0; j < chunk.blk_num; j++){
        memset(chunk.blocks[j].m, 0, sizeof(chunk.blocks[j].m));
        for (int k = j*16; k < j*16+16 && k < last_index; k++){
            // if (k + 1 > len_words) chunk.blocks[j].m[k] = 0;
            chunk.blocks[j].m[k-j*16] = message[k];
        }
    }

    uint32_t h[8] = {0};
    process_chunk(&chunk, h);

    // printf("\n\n\n");
    // printf("0x");
    for (int i = 0; i < 8; i++){
        // printf("%x ", __bswap_32(h[i]));
        chunk.hash[i] = (h[i]); // check here
    }
    // printf("\n");
    return chunk;
}

/* "IETF" = 0x 49 45 54 46 */
int main(int argc, char **argv){
    uint64_t input_size; 
    printf("#msg bytes: ");
    scanf("%lu", &input_size);
    printf("msg:\n");
    uint64_t chunk_num = input_size/1024 + (input_size%1024 != 0);
    bchunk msg[chunk_num];
    for(int i = 0; i < chunk_num; i++){
        uint64_t len_bytes = 1024;
        if (i == chunk_num-1) len_bytes = input_size - (i*1024);

        msg[i] = read_chunk(len_bytes, i, chunk_num);
        for (int j = 0; j < 8; j++){
            printf("%x", __bswap_32(msg[i].hash[j]));
        }
        printf("\n");
    }

    // process_BT(msg, chunk_num);

    return 0;
}
