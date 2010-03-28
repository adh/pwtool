SRCS       = pwtool.c sha256.c prng.c encryption.c aes.c
CFLAGS     = -g -Wall 
LDADD      = -lgc -ltokyocabinet -lreadline
MAKEDEPEND = @echo "  DEP " $<; gcc -M $(CPPFLAGS) -o $(df).d $<
LDC        = @echo "  LD  " $@; gcc $(LDFLAGS) 
CCC        = @echo "  CC  " $@; gcc $(CFLAGS)
DEPDIR     = .deps

.PHONY: dep-init all clean

all: dep-init pwtool
clean:
	rm -f pwtool
	rm -f *.o
	rm -f *.P

pwtool: $(SRCS:.c=.o)
	$(LDC) -o pwtool $(SRCS:.c=.o) $(LDADD)

df = $(DEPDIR)/$(*F)

%.o : %.c
	@if [ ! -d $(DEPDIR) ]; then mkdir $(DEPDIR); fi;
	$(MAKEDEPEND); \
	cp $(df).d $(df).P; \
	sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
	    -e '/^$$/ d' -e 's/$$/ :/' < $(df).d >> $(df).P; \
	rm -f $(df).d
	$(CCC) -o $@ -c $<

-include $(SRCS:%.c=$(DEPDIR)/%.P)
