rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting known steps in traces"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 7E 03 F6 FF FF C9 }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { 3D C0 10 00 00 00 00 00 00 0F 82 FF }

    condition:
        (any of them)
}