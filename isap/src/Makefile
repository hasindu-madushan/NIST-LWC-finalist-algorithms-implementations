std=c99
src=isap.c ../../utils/hex_utils.c ../../ascon/src/ascon_permutation.c 

isap: $(src)
	gcc -std=$(std) -o $@ $(src) 

clean:
	rm isap.exe
