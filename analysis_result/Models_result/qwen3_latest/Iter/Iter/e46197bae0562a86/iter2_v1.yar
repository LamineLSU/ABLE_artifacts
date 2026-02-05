rule Bypass_Sample
{
    meta:
        description = "Detects a sequence of instructions leading to an exit call with potential bypass logic"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2023-10-05"

    strings:
        $pattern0 = { 6A ?? E8 ?? ?? ?? ?? } // push ebx followed by call to CloseHandle
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? } // test eax, eax followed by jz
        $pattern2 = { E8 ?? ?? ?? ?? 85 C0 } // call to CloseHandle followed by test eax, eax

    condition:
        all of them
}