rule ConditionalJump {
      meta:
          description = "Conditional jump after comparison"
        cape_options = "bp0=$a+0,action0=skip,count=0"
      strings:
          $a = { 83 F8 01 74 ?? ?? ?? ?? }
      condition: $a
  }