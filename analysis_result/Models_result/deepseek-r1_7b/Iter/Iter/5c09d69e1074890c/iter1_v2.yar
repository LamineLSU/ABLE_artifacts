rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 8B 45 FC }  ; TEST followed by JE
        $pattern1 = { E8 74 0A 00 00 } ; Conditional jump before exit
        $pattern2 = { 3D F8 01 74 12 8B 4D F8 }  ; Unique instruction sequence after call
}

    condition:
        any of them
}