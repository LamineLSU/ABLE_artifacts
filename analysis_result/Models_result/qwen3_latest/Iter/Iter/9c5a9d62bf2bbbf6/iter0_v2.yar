rule ExampleRule
{
    meta:
        description = "Example rule for detecting specific patterns"
    strings:
        $a = { 53 FF15 ?? ?? ?? ?? }  // push ebx followed by call to ExitProcess
        $b = { 85 C0 0F84 ?? ?? ?? ?? }  // test eax, eax followed by je
        $c = { 8B 45 08 E8 ?? ?? ?? ?? }  // mov eax, [ebp+08h] followed by call
    condition:
        all of them
}