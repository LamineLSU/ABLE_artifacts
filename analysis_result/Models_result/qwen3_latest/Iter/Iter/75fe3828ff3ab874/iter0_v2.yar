rule SandboxCheck
{
    meta:
        description = "Detects sandbox detection code by identifying common sandbox check patterns."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { 53 FF 15 ?? ?? ?? ?? }  // push ebx followed by call to ExitProcess
        $b = { 50 FF 15 ?? ?? ?? ?? }  // push eax followed by call to CloseHandle
        $c = { 8B 45 08 E8 ?? ?? ?? ?? }  // mov eax, [ebp+08] followed by call to some function

    condition:
        all of ($a, $b, $c)
}