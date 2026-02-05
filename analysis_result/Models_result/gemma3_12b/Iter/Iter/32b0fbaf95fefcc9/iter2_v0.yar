rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 91 80 00 00 00 FF D2 }  // mov edx, dword ptr [ecx+00000080h]; call edx
        $pattern1 = { 8B 45 F8 50 8B 4D 08 51 50 } // mov eax, dword ptr [ebp-08h]; push eax; mov ecx, dword ptr [ebp+08h]; push ecx; push eax
        $pattern2 = { 8B 51 48 8B 55 FC 89 8A B0 00 00 00 } // mov edx, dword ptr [ecx+48h]; mov edx, dword ptr [ebp-04h]; mov dword ptr [edx+000000B0h], ecx

    condition:
        any of them
}