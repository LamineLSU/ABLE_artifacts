rule Bypass_Sample {
    meta:
        description: "Evasion bypass rule targeting sample traces"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B45FC ?? ?? ?? ?? }
        $pattern1 = { E874FEFFFF ?? ?? ?? ?? ?? ?? }
        $pattern2 = { FF15C07C4200 ?? ?? ?? ?? }

    condition:
        any of them
}