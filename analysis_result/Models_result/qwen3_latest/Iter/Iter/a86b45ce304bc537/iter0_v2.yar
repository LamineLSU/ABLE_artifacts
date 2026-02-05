rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 54 24 08 }  // Call to 0041A950h followed by mov edx
        $pattern1 = { E8 ?? ?? ?? ?? 8B 4D 08 }     // Call to 0041A0BA followed by mov ecx
        $pattern2 = { 83 C4 14 52 FF D0 }            // Add esp, push edx, call eax

    condition:
        all of them
}