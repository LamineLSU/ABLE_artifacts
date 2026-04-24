rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 08 3D 46 00 8D 4C 24 1C } // push 00463D08; lea ecx, dword ptr [esp+1Ch]
        $pattern1 = { 53 50 8D 4C 24 20 E8 38 F5 FF FF } // push ebx; push eax; lea ecx, dword ptr [esp+20h]; call 0040245Ch
        $pattern2 = { 68 08 3D 3F 03 8D 4C 24 2C } // push 033F3D08; lea ecx, dword ptr [esp+2Ch]

    condition:
        any of them
}