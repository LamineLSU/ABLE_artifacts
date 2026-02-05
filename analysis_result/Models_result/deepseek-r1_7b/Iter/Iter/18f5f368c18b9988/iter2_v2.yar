rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit process calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC FF 15 88 00 26 00 }  # Bypass first API call
        $pattern1 = { 8B 45 FC FF 15 60 00 26 00 }  # Bypass second API call
        $pattern2 = { 83 F8 01 74 74 27 }      # Bypass conditional jump before exit

    condition:
        any of them
}