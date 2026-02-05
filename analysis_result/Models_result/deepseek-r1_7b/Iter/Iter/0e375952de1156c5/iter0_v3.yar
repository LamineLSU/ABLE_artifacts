rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting exitprocess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {  }
        $pattern1 = {  }
        $pattern2 = {  }

    condition:
        any of them
}