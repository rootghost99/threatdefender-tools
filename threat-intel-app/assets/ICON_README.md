# Application Icon

To complete the Windows installer setup, add an `icon.ico` file to this directory.

## Requirements

- **Format**: Windows ICO format
- **Sizes**: Should include multiple sizes (16x16, 32x32, 48x48, 256x256)
- **Filename**: `icon.ico`

## Creating an Icon

You can create an icon using:

1. **Online Tools**:
   - https://icoconvert.com/
   - https://convertio.co/png-ico/

2. **Design Tools**:
   - Adobe Illustrator → Export as ICO
   - Figma → Export PNG, then convert to ICO
   - GIMP → Save as ICO

## Suggested Design

For a threat intelligence tool, consider:
- Shield icon
- Magnifying glass with shield
- Network/globe with security elements
- Dark blue/purple color scheme

## After Adding Icon

The electron-builder configuration in `package.json` will automatically use `assets/icon.ico` for:
- Application window icon
- Taskbar icon
- Desktop shortcut
- Start Menu entry
- Installer graphics
