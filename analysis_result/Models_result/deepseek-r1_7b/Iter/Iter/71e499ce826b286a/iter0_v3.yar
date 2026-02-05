rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting TEST EAX, JZX offset check, and conditional jump"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 09 6C ?? ??.??.?? JZX ?? ?? 8B 45 }
        $pattern1 = { 74 ?A 74 ?? 83 C4 8B 45 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}