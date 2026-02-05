rule TestAfterGetModuleHandleA
       meta:
           description = "Detects test after GetModuleHandleA followed by a JE"
        cape_options = "bp0=$a+0,action0=skip,count=0"
       strings:
           $a = { 85 C0 74 ?? }
       condition:
           $a