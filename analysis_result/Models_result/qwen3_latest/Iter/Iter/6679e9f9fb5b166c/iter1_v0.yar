rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 00 00 00 00 E8 ?? ?? ?? ?? }  // Push 0x00000000 + call to ExitProcess
        $pattern1 = { 8B 45 F8 E8 D9 CE FF FF }         // mov eax, [ebp-00000278h] + call to 00403D98h
        $pattern2 = { BA 03 00 00 00 E8 55 C3 FE FF }  // mov edx, 0x00000003 + call to 00403E78h

    condition:
        all of them
}