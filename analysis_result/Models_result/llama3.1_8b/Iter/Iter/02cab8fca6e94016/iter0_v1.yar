rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 85 C0 0F 84 ?? ?? ?? ?? 8B 45 }
        $pattern1 = { 20 FF EE CE 0F 84 ?? ?? ?? ?? FF 35 ?? ?? ?? E8 ?? ?? ?? ?? }
        $pattern2 = { 20 FF EE CE 59 E8 C8 FF FF FF FF 8B CE E8 ?? ?? ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}