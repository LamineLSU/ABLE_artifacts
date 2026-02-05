rule example_rule
{
    strings:
        $a = /FF 75 08 E8 ?? ?? ?? ??/
        $b = /59 FF 15 ?? ?? ?? ??/
        $c = /55 8B EC FF 75 08/
    condition:
        any of them
}