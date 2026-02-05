rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 7C 58 68 10 68 26 00 FF 75 08 } //Push 0x7Ch, Pop eax, Push 0x266810, Push 0x266810, Push dword ptr [ebp+08h]
        $pattern1 = { 68 18 68 26 00 50 FF 15 B8 E3 48 00 85 C0 } // Push 0x266818, Push 0x266810, Push eax, Call dword ptr [0048E3B8h], Test eax, eax
        $pattern2 = { 8B 45 F4 50 8D 45 FC 50 FF 75 08 FF 15 5C 02 26 00 } //Mov ecx, dword ptr [ebp-0Ch], Push eax, Lea eax, dword ptr [ebp-04h], Push eax, Push dword ptr [ebp+08h], Call dword ptr [0026025Ch]

    condition:
        any of them
}