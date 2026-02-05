rule Pattern1
  {
      meta:
          description = "Call to ExitProcess with preceding instructions"
        cape_options = "bp0=$a+0,action0=skip,count=0"
      strings:
          $a = { E8 ?? ?? ?? ?? 59 FF 75 08 }
      condition:
          $a
  }