std=c99
utils_src=../../utils/hex_utils.c
xoodoo_src=xoodoo.c $(utils_src)
src=xoodyak.c xoodoo.c $(utils_src)
xoodoo_test=XOODOO_TEST

xoodyak: $(src)
	gcc -std=$(std) -o $@ $(src)

xoodoo: $(xoodoo_src)
	gcc -std=$(std) -D $(xoodoo_test) -o $@ $(xoodoo_src)

clean:
	rm xoodyak.exe
