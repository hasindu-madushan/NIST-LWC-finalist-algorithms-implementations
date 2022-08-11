std = c99
src = ascon.c ../../utils/hex_utils.c ascon_permutation.c

ascon: $(src)
	gcc -std=$(std) -o $@ $(src)

clean:
	rm ascon.exe
