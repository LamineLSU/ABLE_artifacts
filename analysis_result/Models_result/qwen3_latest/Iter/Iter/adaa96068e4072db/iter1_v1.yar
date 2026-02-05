rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 FF D0 }  // Push edx + Call eax (ExitProcess)
        $pattern1 = { E8 04 13 00 00 }  // Call to 0041F143h
        $pattern2 = { 8B 16 50 51 FF D2 }  // Mov edx,[esi] + Push eax/ecx + Call edx

    condition:
        any of them
}