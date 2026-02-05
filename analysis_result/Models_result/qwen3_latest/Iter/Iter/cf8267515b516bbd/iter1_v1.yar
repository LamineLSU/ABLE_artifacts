rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 55 8B EC }  // Call to RtlAllocateHeap followed by push ebp/mov ebp
        $pattern1 = { E8 ?? ?? ?? ?? 68 00 00 00 3C }  // Call to 00418DB0h followed by push 0000003Ch
        $pattern2 = { 80 2D ?? ?? ?? ?? }  // Sub byte ptr [ecx+...], dh (potential check)

    condition:
        any of them
}