rule Bypass_Sample {
    meta:
        description: "Evasion bypass rule targeting specific patterns"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B45D8 51 48 E8 ?? ?? ?? ?? }
        $pattern1 = { FF7508 F6 FF7508 FF C3 ?? }
        $pattern2 = { 8F45FC 85 C0 0F 84 ?? ?? ?? }

    condition:
        any of them
}