std = c99
src = elephant.c ../../utils/hex_utils.c spongent.c

elephant: $(src)
	gcc -std=$(std) -o $@ $(src)

clean:
	rm elephant.exe
