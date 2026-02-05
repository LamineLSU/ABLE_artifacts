rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule based on observed sandbox/VM behavior"
        cape_options = "bp0=E8F7250000,action0=skip,bp1=FF153CF14200,action1=skip,bp2=FF15A0F14200,action2=skip,count=0"

    strings:
        $pattern0 = { E8  F7 25 00  8B  45 ?? ?? ?? ?? } 
        $pattern1 = { FF 15 3C F1 42 00 E8 ?? ?? ?? ?? }
        $pattern2 = { FF 15 A0 F1 42 00 ??.??.???.??? }

    condition:
        any of them
}