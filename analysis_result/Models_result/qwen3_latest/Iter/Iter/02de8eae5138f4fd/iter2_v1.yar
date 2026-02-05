rule SpecificFunctionCalls
{
    meta:
        description = "Identifies specific function calls: GetModuleHandleA, GetCommandLineA, CreateThread"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? } // push + call to GetModuleHandleA
        $b = { 8B 0D ?? ?? ?? ?? E8 95 10 00 00 } // mov + call to GetCommandLineA
        $c = { 68 ?? ?? ?? ?? E8 39 10 00 00 } // push + call to CreateThread

    condition:
        any of ($a, $b, $c)
}