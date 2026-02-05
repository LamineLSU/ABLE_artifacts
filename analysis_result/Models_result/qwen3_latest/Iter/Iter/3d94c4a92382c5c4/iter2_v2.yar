rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D3 46 83 FE 1A 0F 8C ?? ?? ?? ?? }  // Sleep call + cmp esi, 1Ah + jl
        $pattern1 = { FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? }  // WaitForSingleObject call + test eax + jne
        $pattern2 = { 68 ?? ?? ?? ?? FF D3 }  // Push + Sleep call (second instance)

    condition:
        any of them
}