rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 05 8B 45 FC }  // cmp eax,11h + je + mov eax, [ebp-04]
        $pattern1 = { FF 15 FC 64 45 00 50 89 45 FC }  // call VirtualAllocExNuma + push eax + mov [ebp-04], eax
        $pattern2 = { 83 7D FC 00 75 08 8B 4D FC }  // cmp [ebp-04],0 + jne + mov eax, [ebp-04]

    condition:
        any of them
}