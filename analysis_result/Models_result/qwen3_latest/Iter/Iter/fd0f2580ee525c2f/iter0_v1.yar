rule MaliciousControlFlow
{
    meta:
        description = "Detects potential control flow hijacking or API call patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { 53 FF 15 ?? ?? ?? ?? }  // push ebx, call
        $b = { 8B D8 74 ?? ?? ?? ?? }  // test eax, je
        $c = { 51 E8 ?? ?? ?? ?? }     // push ecx, call

    condition:
        any of them
}