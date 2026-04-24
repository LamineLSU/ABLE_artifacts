rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 01 83 EC 18 8B CC 53 E8 AC 9E FF FF } //TRACE //1 - Skipping push 1, sub esp, 18, mov ecx, esp, push ebx, call 00408098
        $pattern1 = { FF 15 AC 63 45 00 FF 75 08 FF 15 54 63 45 00 } //TRACE //2 - Skipping call dword ptr [004563ACh] and push dword ptr [ebp+08h]
        $pattern2 = { 68 48 3E 46 00 8D 4D E8 E8 01 C1 FF FF } //TRACE //4 - Skipping push 00463E48, lea ecx, dword ptr [ebp-18h], call 0040808E

    condition:
        any of them
}