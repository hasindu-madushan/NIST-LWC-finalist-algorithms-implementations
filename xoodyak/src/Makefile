std=c99
utils_src=../../utils/hex_utils.c
xoodoo_src=xoodoo.c $(utils_src)
src=xoodyak.c xoodoo.c $(utils_src)
xoodoo_test=XOODOO_TEST
args=-std=$(std) -g

xoodyak: $(src)
	gcc $(args) -o $@ $(src)

xoodoo: $(xoodoo_src)
	gcc $(args) -D $(xoodoo_test) -o $@ $(xoodoo_src)

clean:
	rm xoodyak.exe
