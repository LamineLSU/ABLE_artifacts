rule ConditionalBranch
  {
      meta:
          description = "Conditional jump after test and push"
        cape_options = "bp0=$a+0,action0=skip,count=0"
      strings:
          $a = { 85 C0 74 ?? 6A 5B }
      condition:
          $a
  }