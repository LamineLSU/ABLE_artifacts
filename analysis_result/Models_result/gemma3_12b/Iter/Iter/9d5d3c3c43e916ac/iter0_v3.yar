rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF 59 } //Target 1: call 0040E7C3h - 13 bytes
        $pattern1 = { FF 75 08 FF 15 AC B0 41 00 } //Target 2: call dword ptr [0041B0ACh] - 9 bytes
        $pattern2 = { 55 8B EC FF 75 08 } //Target 3: push dword ptr [ebp+08h] - 9 bytes

    condition:
        any of them
}