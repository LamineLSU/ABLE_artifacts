rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 55 E7 F0 83 C4 ?? ?? ?? }  // push ebp followed by context
        $pattern1 = { E8 C8 FF FF FF 8B EC 83 C4 ?? ?? ?? }  // call dword ptr [ebp+08h] and mov ebp, esp
        $pattern2 = { 6A EC 55 E7 F0 83 C4 ?? ?? ?? }  // example pattern for third check

    condition:
        any of them
}