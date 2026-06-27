--!nonstrict
--[[
    Aurora Universal (AIO) — game-agnostic build.
    Loaded by canary.luau's dispatcher on any game that is NOT Counter-Blox.

    Built in phases:
      Phase 1 (this pass): self-contained UI library + flag/registry/teardown spine
      Phase 2: ESP / chams / visuals
      Phase 3: aimbot / triggerbot / combat
      Phase 4: movement / exploits
      Phase 5: misc / fun / wacky
      Phase 6: config save-load + theme manager + keybind menu

    Nothing here depends on a specific game's remotes, schema, or assets.
    UNC/sUNC standalone globals only, all optional ones degrade gracefully.
]]

if getgenv().AuroraUniversalLoaded then
    return warn("[Aurora Universal] Already loaded.")
end
getgenv().AuroraUniversalLoaded = true

----------------------------------------------------------------------
-- HARDENING CORE — cached globals, cloneref'd services, capability probe
----------------------------------------------------------------------
-- Mirrors canary/CBRO's clonefunction cache: clean references captured up-front
-- so game-side __index/__namecall hooks on these APIs can't observe or break
-- our calls, plus a small perf win on hot paths. Every optional executor global
-- is feature-probed (not assumed) so limited executors degrade gracefully.

-- clonefunction may not exist on weaker executors; fall back to identity.
local clonefunction = (type(clonefunction) == "function" and clonefunction) or function(f) return f end
local cloneref      = (type(cloneref) == "function" and cloneref) or function(o) return o end

-- Datatype + stdlib constructors (cloned)
local _Instancenew  = clonefunction(Instance.new)
local _Vector2New   = clonefunction(Vector2.new)
local _Vector3New   = clonefunction(Vector3.new)
local _CFrameNew    = clonefunction(CFrame.new)
local _CFrameAngles = clonefunction(CFrame.Angles)
local _CFrameLookAt = clonefunction(CFrame.lookAt)
local _Color3New    = clonefunction(Color3.new)
local _Color3RGB    = clonefunction(Color3.fromRGB)
local _Color3HSV    = clonefunction(Color3.fromHSV)
local _UDimNew      = clonefunction(UDim.new)
local _UDim2New     = clonefunction(UDim2.new)
local _UDim2Offset  = clonefunction(UDim2.fromOffset)
local _ColorSeq     = clonefunction(ColorSequence.new)
local _ColorSeqKp   = clonefunction(ColorSequenceKeypoint.new)
local _RaycastParams = clonefunction(RaycastParams.new)

-- game / instance methods (cloned off the base classes like canary does)
local _GetService   = clonefunction(game.GetService)
local _FindService  = clonefunction(game.FindService)
local _FindFirstChild        = clonefunction(game.FindFirstChild)
local _FindFirstChildOfClass = clonefunction(game.FindFirstChildOfClass)
local _GetChildren    = clonefunction(game.GetChildren)
local _GetDescendants = clonefunction(game.GetDescendants)
local _IsA            = clonefunction(game.IsA)
local _Destroy        = clonefunction(game.Destroy)
local _Clone          = clonefunction(game.Clone)
local _WaitForChild   = clonefunction(game.WaitForChild)
local _GetPropertyChangedSignal = clonefunction(game.GetPropertyChangedSignal)

-- camera projection (cloned off a throwaway Camera)
local _camProbe = _Instancenew("Camera")
local _WorldToViewportPoint = clonefunction(_camProbe.WorldToViewportPoint)
local _ViewportPointToRay   = clonefunction(_camProbe.ViewportPointToRay)
_camProbe:Destroy()

-- workspace raycast + input (cloned)
local _Raycast = clonefunction(workspace.Raycast)

-- Services (cloneref'd so the game can't compare our handle to detect us)
local Players      = cloneref(_GetService(game, "Players"))
local RunService   = cloneref(_GetService(game, "RunService"))
local UserInput    = cloneref(_GetService(game, "UserInputService"))
local Workspace    = cloneref(workspace)
local Lighting     = cloneref(_GetService(game, "Lighting"))
local TextService  = cloneref(_GetService(game, "TextService"))
local Teams        = cloneref(_GetService(game, "Teams"))
local HttpService  = cloneref(_GetService(game, "HttpService"))
local Stats        = _FindService(game, "Stats")
if Stats then Stats = cloneref(Stats) end

-- input methods (cloned off the service)
local _IsKeyDown            = clonefunction(UserInput.IsKeyDown)
local _GetMouseLocation     = clonefunction(UserInput.GetMouseLocation)
local _IsMouseButtonPressed = clonefunction(UserInput.IsMouseButtonPressed)

local LocalPlayer = Players.LocalPlayer
local Camera      = cloneref(Workspace.CurrentCamera)

----------------------------------------------------------------------
-- Capability probing + executor identity (weao.xyz-style, but runtime)
----------------------------------------------------------------------
local Caps = {}
-- Probe by passing the global's VALUE directly (referencing an undefined global
-- reads as nil in Luau without error). This avoids getfenv, which is removed or
-- sandboxed on exactly the weaker executors we must support.
local function probe(name, value)
    Caps[name] = type(value) == "function"
    return Caps[name]
end

probe("clonefunction", clonefunction)        -- already resolved above (may be the identity fallback)
probe("cloneref", cloneref)
probe("getgenv", getgenv)
probe("getrawmetatable", getrawmetatable)
probe("setrawmetatable", setrawmetatable)
probe("hookmetamethod", hookmetamethod)
probe("hookfunction", hookfunction)
probe("replaceclosure", replaceclosure)
probe("newcclosure", newcclosure)
probe("setreadonly", setreadonly)
probe("getnamecallmethod", getnamecallmethod)
probe("getsenv", getsenv)
probe("getgc", getgc)
probe("getinstances", getinstances)
probe("getnilinstances", getnilinstances)
probe("setfpscap", setfpscap)
probe("setclipboard", setclipboard)
probe("gethui", gethui)
probe("protectgui", protectgui or protect_gui)
probe("identifyexecutor", identifyexecutor)
probe("mouse1click", mouse1click)
probe("mouse1press", mouse1press)
probe("mouse1release", mouse1release)
probe("mousemoverel", mousemoverel)
probe("firetouchinterest", firetouchinterest)
probe("fireproximityprompt", fireproximityprompt)
probe("fireclickdetector", fireclickdetector)
probe("setsimulationradius", setsimulationradius)
probe("getcustomasset", getcustomasset)
probe("request", request or (syn and syn.request) or http_request)
probe("writefile", writefile)
probe("readfile", readfile)
probe("isfile", isfile)
probe("delfile", delfile)
probe("listfiles", listfiles)
probe("makefolder", makefolder)
probe("isfolder", isfolder)

-- Drawing is special (table/userdata, must be usable)
Caps.Drawing = (typeof(Drawing) == "table" or typeof(Drawing) == "userdata")
    and pcall(function() local d = Drawing.new("Square"); d:Remove() end) or false

-- Convenience aliases used across the script (guarded to safe fallbacks)
local gethui       = Caps.gethui and gethui or nil
local setclipboard = Caps.setclipboard and setclipboard or function() end
local protectgui   = protectgui or protect_gui or (syn and syn.protect_gui)
local makefolder   = makefolder
local isfolder     = isfolder
local writefile    = writefile
local readfile     = readfile
local isfile       = isfile
local delfile      = delfile
local listfiles    = listfiles

local HAS_DRAWING = Caps.Drawing
local HAS_FILES   = Caps.writefile and Caps.readfile and Caps.isfile and Caps.makefolder and true or false

-- Executor identity
local ExecutorName, ExecutorVersion = "Unknown", ""
if Caps.identifyexecutor then
    local ok, name, ver = pcall(identifyexecutor)
    if ok and name then ExecutorName, ExecutorVersion = name, ver or "" end
end

----------------------------------------------------------------------
-- Core library object
----------------------------------------------------------------------
local Library = {
    Version       = "Universal v1.0",
    Connections   = {},   -- tracked RBXScriptConnections
    Drawings      = {},   -- tracked Drawing objects
    Registry      = {},   -- {Instance, Properties} for live theme updates
    RegistryMap   = {},   -- Instance -> registry entry
    OpenedFrames  = {},   -- frames that capture mouse for click-through guarding
    Toggles       = {},   -- flag -> toggle object
    Options       = {},   -- flag -> option object (slider/dropdown/keypicker/colorpicker)
    Flags         = {},   -- flag -> current value (the public read surface)
    Tabs          = {},
    Unloaded      = false,
    Folder        = "AuroraUniversal",

    -- Theme (mutable; ThemeManager rewrites these)
    Theme = {
        Accent      = Color3.fromRGB(255, 140, 0),
        AccentDark  = Color3.fromRGB(170, 90, 0),
        Background  = Color3.fromRGB(13, 13, 13),
        Main        = Color3.fromRGB(20, 20, 20),
        MainLight   = Color3.fromRGB(32, 32, 32),
        Outline     = Color3.fromRGB(40, 40, 40),
        Font        = Color3.fromRGB(235, 235, 235),
        FontDark    = Color3.fromRGB(150, 150, 150),
        Risk        = Color3.fromRGB(255, 60, 60),
        Black       = Color3.fromRGB(0, 0, 0),
    },
    FontFace = Enum.Font.Gotham,
    FontBold = Enum.Font.GothamBold,
}
getgenv().AuroraLibrary = Library

----------------------------------------------------------------------
-- Utility: connection / drawing tracking, notifications
----------------------------------------------------------------------
function Library:Connect(signal, fn)
    local c = signal:Connect(fn)
    self.Connections[#self.Connections + 1] = c
    return c
end

function Library:GiveSignal(c)
    self.Connections[#self.Connections + 1] = c
    return c
end

function Library:NewDrawing(class, props)
    local d = Drawing.new(class)
    for k, v in pairs(props or {}) do d[k] = v end
    self.Drawings[#self.Drawings + 1] = d
    return d
end

function Library:SafeCallback(fn, ...)
    if type(fn) ~= "function" then return end
    local ok, err = pcall(fn, ...)
    if not ok then
        warn("[Aurora Universal] callback error: " .. tostring(err))
    end
end

----------------------------------------------------------------------
-- Instance creation + theme registry
----------------------------------------------------------------------
function Library:Create(class, props)
    local inst = type(class) == "string" and Instance.new(class) or class
    for prop, val in pairs(props or {}) do
        if prop ~= "Parent" then inst[prop] = val end
    end
    if props and props.Parent then inst.Parent = props.Parent end
    return inst
end

-- props map: { RobloxProperty = "ThemeKey" } so theme changes propagate live.
function Library:AddToRegistry(inst, props)
    local data = { Instance = inst, Properties = props }
    self.Registry[#self.Registry + 1] = data
    self.RegistryMap[inst] = data
    -- apply immediately
    for prop, key in pairs(props) do
        if type(key) == "string" then
            inst[prop] = self.Theme[key]
        elseif type(key) == "function" then
            inst[prop] = key()
        end
    end
    return data
end

function Library:RemoveFromRegistry(inst)
    local data = self.RegistryMap[inst]
    if not data then return end
    for i = #self.Registry, 1, -1 do
        if self.Registry[i] == data then table.remove(self.Registry, i) end
    end
    self.RegistryMap[inst] = nil
end

function Library:UpdateTheme()
    for _, data in ipairs(self.Registry) do
        if data.Instance and data.Instance.Parent then
            for prop, key in pairs(data.Properties) do
                if type(key) == "string" then
                    data.Instance[prop] = self.Theme[key]
                elseif type(key) == "function" then
                    data.Instance[prop] = key()
                end
            end
        end
    end
end

function Library:Corner(parent, radius)
    return self:Create("UICorner", { CornerRadius = UDim.new(0, radius or 4), Parent = parent })
end

function Library:Stroke(parent, key)
    local s = self:Create("UIStroke", {
        Color = self.Theme[key or "Outline"],
        Thickness = 1,
        Parent = parent,
    })
    self:AddToRegistry(s, { Color = key or "Outline" })
    return s
end

function Library:GetTextBounds(text, size, font)
    local ok, b = pcall(function()
        return TextService:GetTextSize(text, size, font or self.FontFace, Vector2.new(math.huge, math.huge))
    end)
    if ok then return b.X, b.Y end
    return #tostring(text) * size * 0.5, size
end

----------------------------------------------------------------------
-- ScreenGui host
----------------------------------------------------------------------
local ScreenGui = Instance.new("ScreenGui")
ScreenGui.Name = "AuroraU_" .. tostring(math.random(100000, 999999))
ScreenGui.ResetOnSpawn = false
ScreenGui.ZIndexBehavior = Enum.ZIndexBehavior.Global
ScreenGui.DisplayOrder = 0x7fffffff
pcall(function() if protectgui then protectgui(ScreenGui) end end)
ScreenGui.Parent = (gethui and gethui()) or cloneref(LocalPlayer:WaitForChild("PlayerGui"))
Library.ScreenGui = ScreenGui

-- Rainbow accent driver (used by themes that opt in)
do
    local hue, acc = 0, 0
    Library:Connect(RunService.RenderStepped, function(dt)
        acc = acc + dt
        if acc < (1/60) then return end
        acc = 0
        hue = (hue + 1/400) % 1
        Library.RainbowColor = Color3.fromHSV(hue, 0.8, 1)
    end)
end

----------------------------------------------------------------------
-- Mouse-over guard (so clicks behind open dropdowns/pickers don't pass through)
----------------------------------------------------------------------
function Library:MouseOverFrame(frame)
    local m = UserInput:GetMouseLocation()
    local p, s = frame.AbsolutePosition, frame.AbsoluteSize
    return m.X >= p.X and m.X <= p.X + s.X and m.Y >= p.Y and m.Y <= p.Y + s.Y
end

function Library:MouseOverOpenedFrame()
    for frame in pairs(self.OpenedFrames) do
        if frame.Visible and self:MouseOverFrame(frame) then return true end
    end
    return false
end

----------------------------------------------------------------------
-- Draggable
----------------------------------------------------------------------
function Library:MakeDraggable(handle, target)
    target = target or handle
    local dragging, startPos, startMouse
    self:Connect(handle.InputBegan, function(i)
        if i.UserInputType == Enum.UserInputType.MouseButton1 and not self:MouseOverOpenedFrame() then
            dragging = true
            startPos = target.Position
            startMouse = UserInput:GetMouseLocation()
        end
    end)
    self:Connect(UserInput.InputChanged, function(i)
        if dragging and i.UserInputType == Enum.UserInputType.MouseMovement then
            local m = UserInput:GetMouseLocation()
            local d = m - startMouse
            target.Position = UDim2.new(
                startPos.X.Scale, startPos.X.Offset + d.X,
                startPos.Y.Scale, startPos.Y.Offset + d.Y
            )
        end
    end)
    self:Connect(UserInput.InputEnded, function(i)
        if i.UserInputType == Enum.UserInputType.MouseButton1 then dragging = false end
    end)
end

----------------------------------------------------------------------
-- Notifications
----------------------------------------------------------------------
local NotifyHolder = Library:Create("Frame", {
    Name = "Notifications",
    BackgroundTransparency = 1,
    Position = UDim2.new(1, -310, 1, -10),
    AnchorPoint = Vector2.new(0, 1),
    Size = UDim2.fromOffset(300, 400),
    Parent = ScreenGui,
})
Library:Create("UIListLayout", {
    Padding = UDim.new(0, 6),
    VerticalAlignment = Enum.VerticalAlignment.Bottom,
    SortOrder = Enum.SortOrder.LayoutOrder,
    Parent = NotifyHolder,
})

function Library:Notify(text, duration)
    duration = duration or 4
    local w = math.clamp(select(1, self:GetTextBounds(text, 14)) + 24, 120, 290)
    local outer = self:Create("Frame", {
        BackgroundColor3 = self.Theme.Main,
        Size = UDim2.fromOffset(w, 30),
        ClipsDescendants = true,
        Parent = NotifyHolder,
    })
    self:Corner(outer, 4)
    self:AddToRegistry(outer, { BackgroundColor3 = "Main" })
    local bar = self:Create("Frame", {
        BackgroundColor3 = self.Theme.Accent,
        BorderSizePixel = 0,
        Size = UDim2.new(0, 3, 1, 0),
        Parent = outer,
    })
    self:AddToRegistry(bar, { BackgroundColor3 = "Accent" })
    local lbl = self:Create("TextLabel", {
        BackgroundTransparency = 1,
        Position = UDim2.fromOffset(10, 0),
        Size = UDim2.new(1, -14, 1, 0),
        Font = self.FontFace,
        Text = tostring(text),
        TextColor3 = self.Theme.Font,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = outer,
    })
    self:AddToRegistry(lbl, { TextColor3 = "Font" })
    task.delay(duration, function()
        if outer and outer.Parent then
            pcall(function() outer:TweenSize(UDim2.fromOffset(0, 30), "Out", "Quad", 0.25, true) end)
            task.wait(0.25)
            self:RemoveFromRegistry(outer)
            self:RemoveFromRegistry(bar)
            self:RemoveFromRegistry(lbl)
            outer:Destroy()
        end
    end)
end

----------------------------------------------------------------------
-- Window
----------------------------------------------------------------------
function Library:CreateWindow(cfg)
    cfg = cfg or {}
    local Window = { Tabs = {}, TabButtons = {} }

    local Outer = self:Create("Frame", {
        Name = "Window",
        BackgroundColor3 = self.Theme.Background,
        BorderSizePixel = 0,
        Position = cfg.Position or UDim2.fromOffset(120, 80),
        Size = cfg.Size or UDim2.fromOffset(640, 520),
        Active = true,
        Visible = true,
        Parent = ScreenGui,
    })
    self:Corner(Outer, 6)
    self:AddToRegistry(Outer, { BackgroundColor3 = "Background" })
    self:Stroke(Outer, "Outline")
    Window.Main = Outer

    local TopBar = self:Create("Frame", {
        BackgroundColor3 = self.Theme.Main,
        BorderSizePixel = 0,
        Size = UDim2.new(1, 0, 0, 32),
        Parent = Outer,
    })
    self:Corner(TopBar, 6)
    self:AddToRegistry(TopBar, { BackgroundColor3 = "Main" })
    self:MakeDraggable(TopBar, Outer)

    self:Create("TextLabel", {
        BackgroundTransparency = 1,
        Position = UDim2.fromOffset(12, 0),
        Size = UDim2.new(1, -24, 1, 0),
        Font = self.FontBold,
        Text = cfg.Title or "Aurora Universal",
        TextColor3 = self.Theme.Accent,
        TextSize = 15,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = TopBar,
    })
    local accentLabel = self:Create("TextLabel", {
        BackgroundTransparency = 1,
        Position = UDim2.fromOffset(12, 0),
        Size = UDim2.new(1, -24, 1, 0),
        Font = self.FontFace,
        Text = self.Version,
        TextColor3 = self.Theme.FontDark,
        TextSize = 11,
        TextXAlignment = Enum.TextXAlignment.Right,
        Parent = TopBar,
    })
    self:AddToRegistry(accentLabel, { TextColor3 = "FontDark" })

    -- Tab button column
    local TabList = self:Create("Frame", {
        BackgroundColor3 = self.Theme.Main,
        BorderSizePixel = 0,
        Position = UDim2.fromOffset(0, 32),
        Size = UDim2.new(0, 130, 1, -32),
        Parent = Outer,
    })
    self:AddToRegistry(TabList, { BackgroundColor3 = "Main" })
    self:Create("UIListLayout", {
        Padding = UDim.new(0, 2),
        SortOrder = Enum.SortOrder.LayoutOrder,
        Parent = TabList,
    })
    self:Create("UIPadding", {
        PaddingTop = UDim.new(0, 6),
        PaddingLeft = UDim.new(0, 6),
        PaddingRight = UDim.new(0, 6),
        Parent = TabList,
    })

    -- Tab content area
    local Content = self:Create("Frame", {
        BackgroundTransparency = 1,
        Position = UDim2.fromOffset(130, 32),
        Size = UDim2.new(1, -130, 1, -32),
        Parent = Outer,
    })
    Window.Content = Content

    function Window:AddTab(name, icon)
        local Tab = { Groupboxes = {}, Name = name }

        local Button = Library:Create("TextButton", {
            BackgroundColor3 = Library.Theme.Background,
            BackgroundTransparency = 1,
            BorderSizePixel = 0,
            Size = UDim2.new(1, 0, 0, 30),
            Font = Library.FontFace,
            Text = (icon and (icon .. "  ") or "") .. name,
            TextColor3 = Library.Theme.FontDark,
            TextSize = 13,
            TextXAlignment = Enum.TextXAlignment.Left,
            AutoButtonColor = false,
            Parent = TabList,
        })
        Library:Create("UIPadding", { PaddingLeft = UDim.new(0, 8), Parent = Button })
        Library:Corner(Button, 4)
        Library:AddToRegistry(Button, { TextColor3 = "FontDark" })

        local Page = Library:Create("ScrollingFrame", {
            BackgroundTransparency = 1,
            BorderSizePixel = 0,
            Size = UDim2.new(1, 0, 1, 0),
            CanvasSize = UDim2.new(),
            ScrollBarThickness = 3,
            ScrollBarImageColor3 = Library.Theme.Accent,
            Visible = false,
            Parent = Content,
        })
        Library:AddToRegistry(Page, { ScrollBarImageColor3 = "Accent" })
        Library:Create("UIPadding", {
            PaddingTop = UDim.new(0, 8), PaddingLeft = UDim.new(0, 8),
            PaddingRight = UDim.new(0, 8), PaddingBottom = UDim.new(0, 8),
            Parent = Page,
        })
        -- two columns
        local Columns = Library:Create("Frame", {
            BackgroundTransparency = 1,
            Size = UDim2.new(1, 0, 1, 0),
            Parent = Page,
        })
        local Left = Library:Create("Frame", {
            BackgroundTransparency = 1,
            Size = UDim2.new(0.5, -4, 1, 0),
            Parent = Columns,
        })
        local Right = Library:Create("Frame", {
            BackgroundTransparency = 1,
            Position = UDim2.new(0.5, 4, 0, 0),
            Size = UDim2.new(0.5, -4, 1, 0),
            Parent = Columns,
        })
        for _, col in ipairs({ Left, Right }) do
            Library:Create("UIListLayout", {
                Padding = UDim.new(0, 8),
                SortOrder = Enum.SortOrder.LayoutOrder,
                Parent = col,
            })
        end
        local layout = Page:FindFirstChildOfClass("UIListLayout")
        Library:Connect(Left:FindFirstChildOfClass("UIListLayout"):GetPropertyChangedSignal("AbsoluteContentSize"), function()
            local lh = Left:FindFirstChildOfClass("UIListLayout").AbsoluteContentSize.Y
            local rh = Right:FindFirstChildOfClass("UIListLayout").AbsoluteContentSize.Y
            Page.CanvasSize = UDim2.fromOffset(0, math.max(lh, rh) + 16)
        end)

        Tab.Page = Page
        Tab.Left = Left
        Tab.Right = Right

        function Tab:Show()
            for _, t in pairs(Window.Tabs) do t:Hide() end
            Page.Visible = true
            Button.TextColor3 = Library.Theme.Accent
            Button.BackgroundTransparency = 0.85
            Button.BackgroundColor3 = Library.Theme.Accent
            if Library.RegistryMap[Button] then
                Library.RegistryMap[Button].Properties.TextColor3 = "Accent"
            end
        end
        function Tab:Hide()
            Page.Visible = false
            Button.TextColor3 = Library.Theme.FontDark
            Button.BackgroundTransparency = 1
            if Library.RegistryMap[Button] then
                Library.RegistryMap[Button].Properties.TextColor3 = "FontDark"
            end
        end

        Library:Connect(Button.MouseButton1Click, function() Tab:Show() end)

        function Tab:AddGroupbox(gname, side)
            return Library:_MakeGroupbox(self, gname, side == "Right" and Right or Left)
        end
        function Tab:AddLeftGroupbox(gname) return self:AddGroupbox(gname, "Left") end
        function Tab:AddRightGroupbox(gname) return self:AddGroupbox(gname, "Right") end

        Window.Tabs[name] = Tab
        if not Window._firstTab then
            Window._firstTab = Tab
            Tab:Show()
        end
        return Tab
    end

    self:MakeDraggable(TopBar, Outer)
    Window.TopBar = TopBar
    return Window
end

----------------------------------------------------------------------
-- Widget/addon tables declared up-front so groupbox metatables bind to the
-- real tables regardless of later definition order.
----------------------------------------------------------------------
Library.Widgets = {}
Library.AddonFuncs = {}

----------------------------------------------------------------------
-- Groupbox (container that auto-resizes; widgets attach via metatable)
----------------------------------------------------------------------
function Library:_MakeGroupbox(tab, name, column)
    local Groupbox = {}

    local Outer = self:Create("Frame", {
        BackgroundColor3 = self.Theme.Main,
        BorderSizePixel = 0,
        Size = UDim2.new(1, 0, 0, 40),
        Parent = column,
    })
    self:Corner(Outer, 5)
    self:AddToRegistry(Outer, { BackgroundColor3 = "Main" })
    self:Stroke(Outer, "Outline")

    self:Create("TextLabel", {
        BackgroundTransparency = 1,
        Position = UDim2.fromOffset(10, 6),
        Size = UDim2.new(1, -20, 0, 16),
        Font = self.FontBold,
        Text = name,
        TextColor3 = self.Theme.Accent,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = Outer,
    })
    local accentLine = self:Create("Frame", {
        BackgroundColor3 = self.Theme.Accent,
        BorderSizePixel = 0,
        Position = UDim2.fromOffset(0, 28),
        Size = UDim2.new(1, 0, 0, 1),
        Parent = Outer,
    })
    self:AddToRegistry(accentLine, { BackgroundColor3 = "Accent" })

    local Container = self:Create("Frame", {
        BackgroundTransparency = 1,
        Position = UDim2.fromOffset(8, 34),
        Size = UDim2.new(1, -16, 1, -42),
        Parent = Outer,
    })
    local list = self:Create("UIListLayout", {
        Padding = UDim.new(0, 6),
        SortOrder = Enum.SortOrder.LayoutOrder,
        Parent = Container,
    })

    Groupbox.Outer = Outer
    Groupbox.Container = Container

    function Groupbox:Resize()
        Outer.Size = UDim2.new(1, 0, 0, 42 + list.AbsoluteContentSize.Y)
    end
    Library:Connect(list:GetPropertyChangedSignal("AbsoluteContentSize"), function()
        Groupbox:Resize()
    end)

    setmetatable(Groupbox, { __index = Library.Widgets })
    tab.Groupboxes[name] = Groupbox
    return Groupbox
end

----------------------------------------------------------------------
-- Widgets (attached to every groupbox via __index)
----------------------------------------------------------------------
local Widgets = Library.Widgets

local function rowFrame(self, height)
    return Library:Create("Frame", {
        BackgroundTransparency = 1,
        Size = UDim2.new(1, 0, 0, height),
        Parent = self.Container,
    })
end

function Widgets:AddLabel(text)
    local row = rowFrame(self, 16)
    local lbl = Library:Create("TextLabel", {
        BackgroundTransparency = 1,
        Size = UDim2.new(1, 0, 1, 0),
        Font = Library.FontFace,
        Text = text,
        TextColor3 = Library.Theme.Font,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = row,
    })
    Library:AddToRegistry(lbl, { TextColor3 = "Font" })
    return { SetText = function(_, t) lbl.Text = t end }
end

function Widgets:AddDivider()
    local row = rowFrame(self, 5)
    local line = Library:Create("Frame", {
        BackgroundColor3 = Library.Theme.Outline,
        BorderSizePixel = 0,
        Position = UDim2.new(0, 0, 0.5, 0),
        Size = UDim2.new(1, 0, 0, 1),
        Parent = row,
    })
    Library:AddToRegistry(line, { BackgroundColor3 = "Outline" })
end

function Widgets:AddToggle(flag, info)
    info = info or {}
    local Toggle = {
        Value = info.Default or false,
        Type = "Toggle",
        Callback = info.Callback,
        Risky = info.Risky,
        Addons = {},
        Flag = flag,
    }
    Library.Flags[flag] = Toggle.Value

    local row = rowFrame(self, 18)
    local box = Library:Create("Frame", {
        BackgroundColor3 = Toggle.Value and Library.Theme.Accent or Library.Theme.MainLight,
        BorderSizePixel = 0,
        Size = UDim2.fromOffset(16, 16),
        Position = UDim2.fromOffset(0, 1),
        Parent = row,
    })
    Library:Corner(box, 3)
    Library:Stroke(box, "Outline")

    local lbl = Library:Create("TextLabel", {
        BackgroundTransparency = 1,
        Position = UDim2.fromOffset(24, 0),
        Size = UDim2.new(1, -24, 1, 0),
        Font = Library.FontFace,
        Text = info.Text or flag,
        TextColor3 = Toggle.Risky and Library.Theme.Risk or Library.Theme.Font,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = row,
    })
    Library:AddToRegistry(lbl, { TextColor3 = Toggle.Risky and "Risk" or "Font" })

    local btn = Library:Create("TextButton", {
        BackgroundTransparency = 1,
        Size = UDim2.new(1, 0, 1, 0),
        Text = "",
        Parent = row,
    })

    function Toggle:Display()
        box.BackgroundColor3 = self.Value and Library.Theme.Accent or Library.Theme.MainLight
        if Library.RegistryMap[box] then
            Library.RegistryMap[box].Properties = Library.RegistryMap[box].Properties or {}
        end
    end
    function Toggle:SetValue(v)
        self.Value = not not v
        Library.Flags[flag] = self.Value
        self:Display()
        for _, addon in ipairs(self.Addons) do
            if addon.Type == "KeyPicker" and addon.SyncToggleState then
                addon.Toggled = self.Value
            end
        end
        Library:SafeCallback(self.Callback, self.Value)
    end
    function Toggle:OnChanged(fn) self.Callback = fn; Library:SafeCallback(fn, self.Value) end

    Library:Connect(btn.MouseButton1Click, function()
        if Library:MouseOverOpenedFrame() then return end
        Toggle:SetValue(not Toggle.Value)
    end)

    Toggle.Row = row
    Library.Toggles[flag] = Toggle
    -- allow :AddKeyPicker chaining
    return setmetatable(Toggle, { __index = Library.AddonFuncs })
end

function Widgets:AddButton(text, callback)
    local row = rowFrame(self, 26)
    local btn = Library:Create("TextButton", {
        BackgroundColor3 = Library.Theme.MainLight,
        BorderSizePixel = 0,
        Size = UDim2.new(1, 0, 1, 0),
        Font = Library.FontFace,
        Text = text,
        TextColor3 = Library.Theme.Font,
        TextSize = 13,
        AutoButtonColor = false,
        Parent = row,
    })
    Library:Corner(btn, 4)
    Library:Stroke(btn, "Outline")
    Library:AddToRegistry(btn, { BackgroundColor3 = "MainLight", TextColor3 = "Font" })
    Library:Connect(btn.MouseEnter, function() btn.BackgroundColor3 = Library.Theme.Accent end)
    Library:Connect(btn.MouseLeave, function() btn.BackgroundColor3 = Library.Theme.MainLight end)
    Library:Connect(btn.MouseButton1Click, function()
        if Library:MouseOverOpenedFrame() then return end
        Library:SafeCallback(callback)
    end)
    return { Instance = btn }
end

function Widgets:AddSlider(flag, info)
    info = info or {}
    local min, max = info.Min or 0, info.Max or 100
    local span = (max - min) ~= 0 and (max - min) or 1
    local rounding = info.Rounding or 0
    local Slider = {
        Value = math.clamp(info.Default or min, min, max),
        Type = "Slider", Flag = flag, Callback = info.Callback,
        Min = min, Max = max,
    }
    Library.Flags[flag] = Slider.Value

    rowFrame(self, 2)
    local lblRow = rowFrame(self, 14)
    local lbl = Library:Create("TextLabel", {
        BackgroundTransparency = 1,
        Size = UDim2.new(1, 0, 1, 0),
        Font = Library.FontFace,
        Text = (info.Text or flag),
        TextColor3 = Library.Theme.Font,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = lblRow,
    })
    Library:AddToRegistry(lbl, { TextColor3 = "Font" })
    local valLbl = Library:Create("TextLabel", {
        BackgroundTransparency = 1,
        Size = UDim2.new(1, 0, 1, 0),
        Font = Library.FontFace,
        Text = "",
        TextColor3 = Library.Theme.FontDark,
        TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Right,
        Parent = lblRow,
    })
    Library:AddToRegistry(valLbl, { TextColor3 = "FontDark" })

    local barRow = rowFrame(self, 10)
    local bar = Library:Create("Frame", {
        BackgroundColor3 = Library.Theme.MainLight,
        BorderSizePixel = 0,
        Size = UDim2.new(1, 0, 0, 8),
        Position = UDim2.fromOffset(0, 1),
        Parent = barRow,
    })
    Library:Corner(bar, 3)
    Library:Stroke(bar, "Outline")
    Library:AddToRegistry(bar, { BackgroundColor3 = "MainLight" })
    local fill = Library:Create("Frame", {
        BackgroundColor3 = Library.Theme.Accent,
        BorderSizePixel = 0,
        Size = UDim2.new((Slider.Value - min) / span, 0, 1, 0),
        Parent = bar,
    })
    Library:Corner(fill, 3)
    Library:AddToRegistry(fill, { BackgroundColor3 = "Accent" })

    local function round(v)
        if rounding == 0 then return math.floor(v + 0.5) end
        local m = 10 ^ rounding
        return math.floor(v * m + 0.5) / m
    end
    function Slider:Display()
        valLbl.Text = tostring(self.Value) .. (info.Suffix or "")
        fill.Size = UDim2.new((self.Value - min) / span, 0, 1, 0)
    end
    function Slider:SetValue(v)
        v = tonumber(v)
        if not v then return end
        self.Value = round(math.clamp(v, min, max))
        Library.Flags[flag] = self.Value
        self:Display()
        Library:SafeCallback(self.Callback, self.Value)
    end
    function Slider:OnChanged(fn) self.Callback = fn; Library:SafeCallback(fn, self.Value) end
    Slider:Display()

    local dragging = false
    local function setFromMouse()
        local w = bar.AbsoluteSize.X
        if w <= 0 then return end
        local rel = math.clamp((UserInput:GetMouseLocation().X - bar.AbsolutePosition.X) / w, 0, 1)
        Slider:SetValue(min + (max - min) * rel)
    end
    Library:Connect(bar.InputBegan, function(i)
        if i.UserInputType == Enum.UserInputType.MouseButton1 and not Library:MouseOverOpenedFrame() then
            dragging = true; setFromMouse()
        end
    end)
    Library:Connect(UserInput.InputChanged, function(i)
        if dragging and i.UserInputType == Enum.UserInputType.MouseMovement then setFromMouse() end
    end)
    Library:Connect(UserInput.InputEnded, function(i)
        if i.UserInputType == Enum.UserInputType.MouseButton1 then dragging = false end
    end)

    Library.Options[flag] = Slider
    return Slider
end

-- Addon funcs (KeyPicker chained onto toggles); table declared up-front above.
function Library.AddonFuncs:AddKeyPicker(flag, info)
    info = info or {}
    local Picker = {
        Type = "KeyPicker", Flag = flag,
        Value = info.Default or "None",
        Mode = info.Mode or "Toggle",
        SyncToggleState = info.SyncToggleState,
        Toggled = false,
        Callback = info.Callback,
    }
    Library.Flags[flag] = Picker.Value
    if self.Addons then self.Addons[#self.Addons + 1] = Picker end

    local lbl = Library:Create("TextLabel", {
        BackgroundTransparency = 1,
        Position = UDim2.new(1, -54, 0, 1),
        Size = UDim2.fromOffset(50, 16),
        Font = Library.FontFace,
        Text = "[" .. tostring(Picker.Value) .. "]",
        TextColor3 = Library.Theme.FontDark,
        TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Right,
        Parent = self.Row,
    })
    Library:AddToRegistry(lbl, { TextColor3 = "FontDark" })
    local btn = Library:Create("TextButton", {
        BackgroundTransparency = 1,
        Position = UDim2.new(1, -54, 0, 1),
        Size = UDim2.fromOffset(50, 16),
        Text = "",
        Parent = self.Row,
    })

    local picking = false
    Library:Connect(btn.MouseButton1Click, function()
        picking = true
        lbl.Text = "[...]"
    end)
    Library:Connect(UserInput.InputBegan, function(i, gpe)
        if picking then
            picking = false
            local key = i.KeyCode ~= Enum.KeyCode.Unknown and i.KeyCode.Name or i.UserInputType.Name
            Picker.Value = key
            Library.Flags[flag] = key
            lbl.Text = "[" .. key .. "]"
            return
        end
        if gpe then return end
        local match = (i.KeyCode.Name == Picker.Value) or (i.UserInputType.Name == Picker.Value)
        if match then
            if Picker.Mode == "Toggle" then
                Picker.Toggled = not Picker.Toggled
                local tog = Library.Toggles[self.Flag]
                if tog and Picker.SyncToggleState then tog:SetValue(Picker.Toggled) end
            end
            Library:SafeCallback(Picker.Callback, Picker.Toggled)
        end
    end)

    function Picker:GetState()
        if self.Mode == "Always" then return true end
        if self.Mode == "Hold" then
            local ok, kc = pcall(function() return Enum.KeyCode[self.Value] end)
            if ok and kc then return UserInput:IsKeyDown(kc) end
            return false
        end
        return self.Toggled
    end
    Library.Options[flag] = Picker
    return self
end

----------------------------------------------------------------------
-- Menu toggle keybind + unload
----------------------------------------------------------------------
function Library:Toggle()
    if self._window then self._window.Main.Visible = not self._window.Main.Visible end
end

Library:Connect(UserInput.InputBegan, function(input, gpe)
    if gpe then return end
    if input.KeyCode == Enum.KeyCode.RightShift then
        Library:Toggle()
    end
end)

function Library:OnUnload(fn)
    -- Additive: every phase can register a teardown without clobbering others.
    self._unloadCallbacks = self._unloadCallbacks or {}
    self._unloadCallbacks[#self._unloadCallbacks + 1] = fn
end
function Library:Unload()
    if self.Unloaded then return end
    self.Unloaded = true
    for _, fn in ipairs(self._unloadCallbacks or {}) do pcall(fn) end
    for _, c in ipairs(self.Connections) do pcall(function() c:Disconnect() end) end
    for _, d in ipairs(self.Drawings) do pcall(function() d:Remove() end) end
    pcall(function() self.ScreenGui:Destroy() end)
    getgenv().AuroraUniversalLoaded = nil
    warn("[Aurora Universal] Unloaded.")
end

-- Keep camera ref fresh.
Library:Connect(Workspace:GetPropertyChangedSignal("CurrentCamera"), function()
    if Workspace.CurrentCamera then Camera = Workspace.CurrentCamera end
end)

----------------------------------------------------------------------
-- Build the window + tabs (features land in later phases)
----------------------------------------------------------------------
local Window = Library:CreateWindow({ Title = "Aurora Universal", Size = UDim2.fromOffset(640, 520) })
Library._window = Window

local Tabs = {
    Combat   = Window:AddTab("Combat"),
    Visuals  = Window:AddTab("Visuals"),
    Movement = Window:AddTab("Movement"),
    World    = Window:AddTab("World"),
    Fun      = Window:AddTab("Fun"),
    Settings = Window:AddTab("Settings"),
}
Library._tabs = Tabs
Library._getChar = function(plr)
    plr = plr or LocalPlayer
    local char = plr.Character
    if not char then return nil end
    local hrp = char:FindFirstChild("HumanoidRootPart") or char:FindFirstChild("Torso") or char:FindFirstChild("UpperTorso")
    local hum = char:FindFirstChildOfClass("Humanoid")
    return char, hum, hrp
end
Library._alive = function(plr)
    local _, hum = Library._getChar(plr)
    return hum ~= nil and hum.Health > 0
end
Library._camera = function() return Camera end

-- Settings tab: unload + menu info (expanded in Phase 6)
do
    local g = Tabs.Settings:AddLeftGroupbox("Menu")
    g:AddLabel("RightShift toggles the menu")
    g:AddButton("Unload Aurora", function() Library:Unload() end)
    local g2 = Tabs.Settings:AddRightGroupbox("Info")
    g2:AddLabel(Library.Version)
    g2:AddLabel("Drawing API: " .. (HAS_DRAWING and "available" or "MISSING"))
    g2:AddLabel("File API: " .. (HAS_FILES and "available" or "missing"))
end

Library:Notify("Aurora Universal loaded — Phase 1 (UI). RightShift to toggle.", 5)

----------------------------------------------------------------------
--                       PHASE 2 — VISUALS / ESP
----------------------------------------------------------------------
do
    local getChar = Library._getChar
    local aliveOf = Library._alive

    local VTab = Tabs.Visuals
    local boxGroup    = VTab:AddLeftGroupbox("Player ESP")
    local infoGroup   = VTab:AddLeftGroupbox("Info")
    local chamGroup   = VTab:AddRightGroupbox("Chams")
    local colorGroup  = VTab:AddRightGroupbox("Colors")

    -- Toggles
    boxGroup:AddToggle("ESP_Enabled",      { Text = "Enabled" })
    boxGroup:AddToggle("ESP_TeamCheck",    { Text = "Team check (ignore teammates)", Default = true })
    boxGroup:AddToggle("ESP_Box",          { Text = "Boxes", Default = true })
    boxGroup:AddToggle("ESP_BoxFilled",    { Text = "Box fill" })
    boxGroup:AddToggle("ESP_Healthbar",    { Text = "Health bar", Default = true })
    boxGroup:AddToggle("ESP_Skeleton",     { Text = "Skeleton" })
    boxGroup:AddToggle("ESP_Tracer",       { Text = "Tracers" })
    -- (tracer origin configurability arrives with the Dropdown widget in Phase 6)
    boxGroup:AddToggle("ESP_OffScreenArrow", { Text = "Off-screen arrows" })
    boxGroup:AddSlider("ESP_MaxDistance",  { Text = "Max distance", Default = 1000, Min = 50, Max = 5000, Rounding = 0 })

    infoGroup:AddToggle("ESP_Name",        { Text = "Names", Default = true })
    infoGroup:AddToggle("ESP_Distance",    { Text = "Distance" })
    infoGroup:AddToggle("ESP_Health",      { Text = "Health text" })
    infoGroup:AddToggle("ESP_Tool",        { Text = "Held tool" })
    infoGroup:AddSlider("ESP_TextSize",    { Text = "Text size", Default = 13, Min = 9, Max = 24, Rounding = 0 })

    chamGroup:AddToggle("Chams_Enabled",   { Text = "Enabled" })
    chamGroup:AddToggle("Chams_OutlineOnly", { Text = "Outline only" })
    chamGroup:AddSlider("Chams_FillTransparency",    { Text = "Fill transparency",    Default = 60, Min = 0, Max = 100, Rounding = 0, Suffix = "%" })
    chamGroup:AddSlider("Chams_OutlineTransparency", { Text = "Outline transparency", Default = 0,  Min = 0, Max = 100, Rounding = 0, Suffix = "%" })

    -- Colors via sliders (R/G/B) until the ColorPicker widget lands in Phase 6.
    local function rgbControls(group, prefix, defR, defG, defB)
        group:AddSlider(prefix .. "_R", { Text = prefix .. " R", Default = defR, Min = 0, Max = 255, Rounding = 0 })
        group:AddSlider(prefix .. "_G", { Text = prefix .. " G", Default = defG, Min = 0, Max = 255, Rounding = 0 })
        group:AddSlider(prefix .. "_B", { Text = prefix .. " B", Default = defB, Min = 0, Max = 255, Rounding = 0 })
    end
    rgbControls(colorGroup, "ESP_EnemyColor", 255, 140, 0)
    rgbControls(colorGroup, "ESP_AllyColor", 60, 170, 255)

    local function flagColor(prefix, fallback)
        local r = Library.Flags[prefix .. "_R"]
        local g = Library.Flags[prefix .. "_G"]
        local b = Library.Flags[prefix .. "_B"]
        if r and g and b then return Color3.fromRGB(r, g, b) end
        return fallback
    end

    -- Is `plr` an enemy relative to LocalPlayer? Universal heuristic: different,
    -- non-neutral team => enemy; same team => ally; no teams => everyone enemy.
    local function isEnemy(plr)
        local lt = LocalPlayer.Team
        local pt = plr.Team
        if lt == nil or pt == nil then return true end
        if pt.Name == "Neutral" then return true end
        return pt ~= lt
    end

    local function targetColor(plr)
        if isEnemy(plr) then
            return flagColor("ESP_EnemyColor", Color3.fromRGB(255, 140, 0))
        end
        return flagColor("ESP_AllyColor", Color3.fromRGB(60, 170, 255))
    end

    ------------------------------------------------------------------
    -- Chams (Highlight-based — works on virtually every game)
    ------------------------------------------------------------------
    local highlights = {}
    local function removeCham(plr)
        local h = highlights[plr]
        if h then pcall(function() h:Destroy() end); highlights[plr] = nil end
    end
    local function updateCham(plr)
        local char = plr.Character
        if not (Library.Flags.Chams_Enabled and char and aliveOf(plr)
            and not (Library.Flags.ESP_TeamCheck and not isEnemy(plr))) then
            removeCham(plr)
            return
        end
        local h = highlights[plr]
        if not h or not h.Parent then
            h = Instance.new("Highlight")
            h.Name = "\0"
            h.Adornee = char
            h.Parent = (gethui and gethui()) or Library.ScreenGui
            highlights[plr] = h
        end
        h.Adornee = char
        local col = targetColor(plr)
        h.FillColor = col
        h.OutlineColor = col
        h.FillTransparency = (Library.Flags.Chams_OutlineOnly and 1)
            or ((Library.Flags.Chams_FillTransparency or 60) / 100)
        h.OutlineTransparency = (Library.Flags.Chams_OutlineTransparency or 0) / 100
        h.DepthMode = Enum.HighlightDepthMode.AlwaysOnTop
    end

    ------------------------------------------------------------------
    -- Drawing-based ESP
    ------------------------------------------------------------------
    if not HAS_DRAWING then
        Library:Notify("Drawing API missing — ESP boxes/tracers disabled; chams still work.", 6)
    end

    local R15_BONES = {
        { "Head", "UpperTorso" }, { "UpperTorso", "LowerTorso" },
        { "UpperTorso", "LeftUpperArm" }, { "LeftUpperArm", "LeftLowerArm" }, { "LeftLowerArm", "LeftHand" },
        { "UpperTorso", "RightUpperArm" }, { "RightUpperArm", "RightLowerArm" }, { "RightLowerArm", "RightHand" },
        { "LowerTorso", "LeftUpperLeg" }, { "LeftUpperLeg", "LeftLowerLeg" }, { "LeftLowerLeg", "LeftFoot" },
        { "LowerTorso", "RightUpperLeg" }, { "RightUpperLeg", "RightLowerLeg" }, { "RightLowerLeg", "RightFoot" },
    }
    local R6_BONES = {
        { "Head", "Torso" },
        { "Torso", "Left Arm" }, { "Torso", "Right Arm" },
        { "Torso", "Left Leg" }, { "Torso", "Right Leg" },
    }

    local espObjects = {}
    local function makeEsp()
        return {
            boxOutline = Library:NewDrawing("Square", { Thickness = 3, Filled = false, Color = Color3.new(), Visible = false }),
            box        = Library:NewDrawing("Square", { Thickness = 1, Filled = false, Color = Color3.new(1,1,1), Visible = false }),
            boxFill    = Library:NewDrawing("Square", { Thickness = 1, Filled = true, Transparency = 0.4, Visible = false }),
            name       = Library:NewDrawing("Text", { Size = 13, Center = true, Outline = true, Color = Color3.new(1,1,1), Visible = false }),
            info       = Library:NewDrawing("Text", { Size = 12, Center = true, Outline = true, Color = Color3.new(1,1,1), Visible = false }),
            tool       = Library:NewDrawing("Text", { Size = 12, Center = true, Outline = true, Color = Color3.new(1,1,1), Visible = false }),
            hpBarBg    = Library:NewDrawing("Square", { Thickness = 1, Filled = true, Color = Color3.new(), Visible = false }),
            hpBar      = Library:NewDrawing("Square", { Thickness = 1, Filled = true, Color = Color3.fromRGB(0,255,0), Visible = false }),
            tracer     = Library:NewDrawing("Line", { Thickness = 1, Color = Color3.new(1,1,1), Visible = false }),
            arrow      = Library:NewDrawing("Triangle", { Thickness = 1, Filled = true, Color = Color3.new(1,1,1), Visible = false }),
            bones      = {},
        }
    end
    local function ensureEsp(plr)
        if espObjects[plr] then return espObjects[plr] end
        local o = HAS_DRAWING and makeEsp() or nil
        espObjects[plr] = o or false
        return espObjects[plr]
    end
    local function hideAll(o)
        if not o then return end
        for _, d in pairs(o) do
            if type(d) == "table" then
                for _, b in pairs(d) do pcall(function() b.Visible = false end) end
            else
                pcall(function() d.Visible = false end)
            end
        end
    end
    local function removeEsp(plr)
        local o = espObjects[plr]
        if o then
            for _, d in pairs(o) do
                if type(d) == "table" then
                    for _, b in pairs(d) do pcall(function() b:Remove() end) end
                else
                    pcall(function() d:Remove() end)
                end
            end
        end
        espObjects[plr] = nil
        removeCham(plr)
    end

    local function getBonePart(char, name)
        return char:FindFirstChild(name)
    end

    -- Render loop
    Library:Connect(RunService.RenderStepped, function()
        if Library.Unloaded then return end
        local cam = Library._camera()
        local enabled = Library.Flags.ESP_Enabled
        local _, _, myHrp = getChar()
        local myPos = myHrp and myHrp.Position

        for _, plr in ipairs(Players:GetPlayers()) do
            if plr == LocalPlayer then continue end
            updateCham(plr)

            local o = ensureEsp(plr)
            if not o then continue end -- no Drawing API

            local char = plr.Character
            local hum  = char and char:FindFirstChildOfClass("Humanoid")
            local hrp  = char and (char:FindFirstChild("HumanoidRootPart") or char:FindFirstChild("Torso"))
            local head = char and (char:FindFirstChild("Head") or hrp)

            local show = enabled and char and hrp and head and hum and hum.Health > 0
            if show and Library.Flags.ESP_TeamCheck and not isEnemy(plr) then show = false end

            local dist = 0
            if show and myPos then
                dist = (hrp.Position - myPos).Magnitude
                if dist > (Library.Flags.ESP_MaxDistance or 1000) then show = false end
            end

            if not show then hideAll(o); continue end

            -- Project bounding box from head-top to feet-bottom.
            local topV, onTop = cam:WorldToViewportPoint(head.Position + Vector3.new(0, 0.7, 0))
            local botV = cam:WorldToViewportPoint(hrp.Position - Vector3.new(0, 3.2, 0))
            local onScreen = onTop and topV.Z > 0

            local col = targetColor(plr)
            local textSize = Library.Flags.ESP_TextSize or 13

            if onScreen then
                local h = math.abs(botV.Y - topV.Y)
                local w = h * 0.5
                local x = topV.X - w / 2
                local y = topV.Y

                -- Box
                if Library.Flags.ESP_Box then
                    o.boxOutline.Size = Vector2.new(w, h); o.boxOutline.Position = Vector2.new(x, y)
                    o.boxOutline.Color = Color3.new(); o.boxOutline.Visible = true
                    o.box.Size = Vector2.new(w, h); o.box.Position = Vector2.new(x, y)
                    o.box.Color = col; o.box.Visible = true
                else
                    o.boxOutline.Visible = false; o.box.Visible = false
                end
                if Library.Flags.ESP_BoxFilled then
                    o.boxFill.Size = Vector2.new(w, h); o.boxFill.Position = Vector2.new(x, y)
                    o.boxFill.Color = col; o.boxFill.Transparency = 0.75; o.boxFill.Visible = true
                else
                    o.boxFill.Visible = false
                end

                -- Health bar (left of box)
                if Library.Flags.ESP_Healthbar and hum.MaxHealth > 0 then
                    local frac = math.clamp(hum.Health / hum.MaxHealth, 0, 1)
                    o.hpBarBg.Size = Vector2.new(3, h); o.hpBarBg.Position = Vector2.new(x - 6, y)
                    o.hpBarBg.Color = Color3.new(); o.hpBarBg.Visible = true
                    o.hpBar.Size = Vector2.new(3, h * frac)
                    o.hpBar.Position = Vector2.new(x - 6, y + h * (1 - frac))
                    o.hpBar.Color = Color3.fromRGB(math.floor(255 * (1 - frac)), math.floor(255 * frac), 0)
                    o.hpBar.Visible = true
                else
                    o.hpBarBg.Visible = false; o.hpBar.Visible = false
                end

                -- Name (above box)
                if Library.Flags.ESP_Name then
                    o.name.Text = plr.DisplayName ~= "" and plr.DisplayName or plr.Name
                    o.name.Size = textSize
                    o.name.Color = col
                    o.name.Position = Vector2.new(topV.X, y - textSize - 2)
                    o.name.Visible = true
                else o.name.Visible = false end

                -- Info line (below box): distance / health
                local infoParts = {}
                if Library.Flags.ESP_Distance then infoParts[#infoParts+1] = tostring(math.floor(dist)) .. "m" end
                if Library.Flags.ESP_Health then infoParts[#infoParts+1] = tostring(math.floor(hum.Health)) .. "hp" end
                if #infoParts > 0 then
                    o.info.Text = table.concat(infoParts, "  ")
                    o.info.Size = textSize
                    o.info.Color = Color3.new(1,1,1)
                    o.info.Position = Vector2.new(topV.X, y + h + 2)
                    o.info.Visible = true
                else o.info.Visible = false end

                -- Held tool
                if Library.Flags.ESP_Tool then
                    local tool = char:FindFirstChildOfClass("Tool")
                    if tool then
                        o.tool.Text = tool.Name
                        o.tool.Size = textSize
                        o.tool.Color = Color3.new(1,1,1)
                        o.tool.Position = Vector2.new(topV.X, y + h + 2 + textSize)
                        o.tool.Visible = true
                    else o.tool.Visible = false end
                else o.tool.Visible = false end

                -- Tracer (from bottom-center of screen to feet)
                if Library.Flags.ESP_Tracer then
                    o.tracer.From = Vector2.new(cam.ViewportSize.X / 2, cam.ViewportSize.Y)
                    o.tracer.To = Vector2.new(botV.X, botV.Y)
                    o.tracer.Color = col
                    o.tracer.Visible = true
                else o.tracer.Visible = false end

                -- Skeleton
                if Library.Flags.ESP_Skeleton then
                    local isR15 = char:FindFirstChild("UpperTorso") ~= nil
                    local bonesSet = isR15 and R15_BONES or R6_BONES
                    for idx, pair in ipairs(bonesSet) do
                        local b = o.bones[idx]
                        if not b then
                            b = Library:NewDrawing("Line", { Thickness = 1, Color = col, Visible = false })
                            o.bones[idx] = b
                        end
                        local p0 = getBonePart(char, pair[1])
                        local p1 = getBonePart(char, pair[2])
                        if p0 and p1 then
                            local v0, on0 = cam:WorldToViewportPoint(p0.Position)
                            local v1, on1 = cam:WorldToViewportPoint(p1.Position)
                            if on0 and on1 and v0.Z > 0 and v1.Z > 0 then
                                b.From = Vector2.new(v0.X, v0.Y)
                                b.To = Vector2.new(v1.X, v1.Y)
                                b.Color = col
                                b.Visible = true
                            else b.Visible = false end
                        else b.Visible = false end
                    end
                else
                    for _, b in pairs(o.bones) do b.Visible = false end
                end

                o.arrow.Visible = false
            else
                -- Off-screen: hide on-screen elements, optionally draw an arrow.
                o.boxOutline.Visible = false; o.box.Visible = false; o.boxFill.Visible = false
                o.name.Visible = false; o.info.Visible = false; o.tool.Visible = false
                o.hpBar.Visible = false; o.hpBarBg.Visible = false; o.tracer.Visible = false
                for _, b in pairs(o.bones) do b.Visible = false end

                if Library.Flags.ESP_OffScreenArrow then
                    local screenCenter = Vector2.new(cam.ViewportSize.X / 2, cam.ViewportSize.Y / 2)
                    local dir = Vector2.new(topV.X, topV.Y) - screenCenter
                    if topV.Z < 0 then dir = -dir end
                    if dir.Magnitude < 1e-3 then dir = Vector2.new(0, -1) end
                    dir = dir.Unit
                    local radius = 120
                    local center = screenCenter + dir * radius
                    local perp = Vector2.new(-dir.Y, dir.X)
                    o.arrow.PointA = center + dir * 14
                    o.arrow.PointB = center - dir * 6 + perp * 8
                    o.arrow.PointC = center - dir * 6 - perp * 8
                    o.arrow.Color = col
                    o.arrow.Filled = true
                    o.arrow.Visible = true
                else
                    o.arrow.Visible = false
                end
            end
        end
    end)

    Library:Connect(Players.PlayerRemoving, removeEsp)

    -- Fold ESP/cham teardown into unload (additive — see Library:OnUnload).
    Library:OnUnload(function()
        for plr in pairs(espObjects) do removeEsp(plr) end
        for plr in pairs(highlights) do removeCham(plr) end
    end)
end

----------------------------------------------------------------------
--                       PHASE 3 — COMBAT
----------------------------------------------------------------------
do
    local getChar = Library._getChar
    local aliveOf = Library._alive

    local CTab = Tabs.Combat
    local aimGroup  = CTab:AddLeftGroupbox("Aimbot")
    local predGroup = CTab:AddLeftGroupbox("Prediction")
    local trigGroup = CTab:AddRightGroupbox("Triggerbot")
    local fovGroup  = CTab:AddRightGroupbox("FOV / Visuals")

    aimGroup:AddToggle("Aim_Enabled", { Text = "Enabled" })
        :AddKeyPicker("Aim_Key", { Default = "E", Mode = "Hold", Text = "Aim key" })
    aimGroup:AddToggle("Aim_TeamCheck", { Text = "Team check", Default = true })
    aimGroup:AddToggle("Aim_VisibleCheck", { Text = "Visible check (wallcheck)", Default = true })
    aimGroup:AddToggle("Aim_Sticky", { Text = "Sticky target (keep until lost)", Default = true })
    aimGroup:AddSlider("Aim_FOV", { Text = "FOV", Default = 120, Min = 10, Max = 500, Rounding = 0, Suffix = "px" })
    aimGroup:AddSlider("Aim_Smoothness", { Text = "Smoothness", Default = 6, Min = 1, Max = 30, Rounding = 0 })
    aimGroup:AddSlider("Aim_MaxDistance", { Text = "Max distance", Default = 2000, Min = 50, Max = 10000, Rounding = 0 })
    -- Hitbox priority list (single for now; Dropdown multi arrives Phase 6)
    aimGroup:AddSlider("Aim_Hitbox", { Text = "Hitbox (1=Head 2=Torso 3=HRP)", Default = 1, Min = 1, Max = 3, Rounding = 0 })

    predGroup:AddToggle("Pred_Enabled", { Text = "Velocity prediction" })
    predGroup:AddSlider("Pred_Strength", { Text = "Prediction strength", Default = 100, Min = 0, Max = 300, Rounding = 0, Suffix = "%" })
    predGroup:AddToggle("Pred_Resolver", { Text = "Air resolver (add gravity)" })

    trigGroup:AddToggle("Trig_Enabled", { Text = "Enabled" })
        :AddKeyPicker("Trig_Key", { Default = "None", Mode = "Hold", Text = "Trigger key" })
    trigGroup:AddToggle("Trig_TeamCheck", { Text = "Team check", Default = true })
    trigGroup:AddToggle("Trig_VisibleCheck", { Text = "Visible check", Default = true })
    trigGroup:AddSlider("Trig_Delay", { Text = "Delay", Default = 30, Min = 0, Max = 500, Rounding = 0, Suffix = "ms" })
    trigGroup:AddSlider("Trig_FOV", { Text = "Hit radius", Default = 6, Min = 1, Max = 60, Rounding = 0, Suffix = "px" })

    fovGroup:AddToggle("FOV_Show", { Text = "Show FOV circle", Default = true })
    fovGroup:AddToggle("FOV_Rainbow", { Text = "Rainbow FOV" })
    fovGroup:AddSlider("FOV_R", { Text = "FOV color R", Default = 255, Min = 0, Max = 255, Rounding = 0 })
    fovGroup:AddSlider("FOV_G", { Text = "FOV color G", Default = 255, Min = 0, Max = 255, Rounding = 0 })
    fovGroup:AddSlider("FOV_B", { Text = "FOV color B", Default = 255, Min = 0, Max = 255, Rounding = 0 })
    fovGroup:AddToggle("FOV_ShowSnapline", { Text = "Snapline to target" })

    ------------------------------------------------------------------
    -- Helpers
    ------------------------------------------------------------------
    local function isEnemy(plr)
        local lt, pt = LocalPlayer.Team, plr.Team
        if lt == nil or pt == nil then return true end
        if pt.Name == "Neutral" then return true end
        return pt ~= lt
    end

    local function hitboxPart(char)
        local pick = Library.Flags.Aim_Hitbox or 1
        if pick == 1 then
            return char:FindFirstChild("Head") or char:FindFirstChild("UpperTorso") or char:FindFirstChild("HumanoidRootPart")
        elseif pick == 2 then
            return char:FindFirstChild("UpperTorso") or char:FindFirstChild("Torso") or char:FindFirstChild("HumanoidRootPart")
        end
        return char:FindFirstChild("HumanoidRootPart") or char:FindFirstChild("Torso") or char:FindFirstChild("Head")
    end

    -- Line-of-sight check from camera to the target part.
    local rayParams = RaycastParams.new()
    rayParams.FilterType = Enum.RaycastFilterType.Exclude
    local function isVisible(part, char)
        local cam = Library._camera()
        local origin = cam.CFrame.Position
        local dir = part.Position - origin
        local myChar = LocalPlayer.Character
        rayParams.FilterDescendantsInstances = { char, myChar, cam }
        local hit = Workspace:Raycast(origin, dir, rayParams)
        return hit == nil -- nothing between camera and target
    end

    -- Apply velocity prediction to a target position.
    local function predictPos(part, hum)
        local pos = part.Position
        if not Library.Flags.Pred_Enabled then return pos end
        local vel = part.AssemblyLinearVelocity
        local strength = (Library.Flags.Pred_Strength or 100) / 100
        -- crude travel-time estimate from distance (universal; no projectile data)
        local cam = Library._camera()
        local dist = (pos - cam.CFrame.Position).Magnitude
        local t = dist / 600 -- assume ~600 studs/s; tunable via strength
        local predicted = pos + vel * t * strength
        if Library.Flags.Pred_Resolver then
            predicted = predicted + Vector3.new(0, -0.5 * Workspace.Gravity * t * t, 0) * strength
        end
        return predicted
    end

    ------------------------------------------------------------------
    -- FOV circle + snapline (Drawing)
    ------------------------------------------------------------------
    local fovCircle, snapline
    if HAS_DRAWING then
        fovCircle = Library:NewDrawing("Circle", {
            Thickness = 1, NumSides = 64, Radius = 120,
            Filled = false, Color = Color3.new(1,1,1), Visible = false,
        })
        snapline = Library:NewDrawing("Line", { Thickness = 1, Color = Color3.new(1,1,1), Visible = false })
    end

    ------------------------------------------------------------------
    -- Target selection (closest to crosshair within FOV)
    ------------------------------------------------------------------
    local currentTarget = nil

    local function validTarget(plr)
        if plr == LocalPlayer then return false end
        if not aliveOf(plr) then return false end
        if Library.Flags.Aim_TeamCheck and not isEnemy(plr) then return false end
        return true
    end

    local function selectTarget()
        local cam = Library._camera()
        local center = Vector2.new(cam.ViewportSize.X / 2, cam.ViewportSize.Y / 2)
        local fov = Library.Flags.Aim_FOV or 120
        local maxDist = Library.Flags.Aim_MaxDistance or 2000
        local _, _, myHrp = getChar()
        local myPos = myHrp and myHrp.Position

        -- Sticky: keep current target if still valid and in FOV.
        if Library.Flags.Aim_Sticky and currentTarget and validTarget(currentTarget) then
            local char = currentTarget.Character
            local part = char and hitboxPart(char)
            if part then
                local v, on = cam:WorldToViewportPoint(part.Position)
                if on and v.Z > 0 and (Vector2.new(v.X, v.Y) - center).Magnitude <= fov then
                    return currentTarget, part
                end
            end
        end

        local best, bestPart, bestScore = nil, nil, fov
        for _, plr in ipairs(Players:GetPlayers()) do
            if validTarget(plr) then
                local char = plr.Character
                local part = char and hitboxPart(char)
                if part then
                    if not myPos or (part.Position - myPos).Magnitude <= maxDist then
                        local v, on = cam:WorldToViewportPoint(part.Position)
                        if on and v.Z > 0 then
                            local d = (Vector2.new(v.X, v.Y) - center).Magnitude
                            if d <= bestScore then
                                best, bestPart, bestScore = plr, part, d
                            end
                        end
                    end
                end
            end
        end
        return best, bestPart
    end

    ------------------------------------------------------------------
    -- Aimbot loop
    ------------------------------------------------------------------
    local function keyHeld(flag)
        local opt = Library.Options[flag]
        if not opt then return true end -- no key bound = always
        local val = opt.Value
        if val == "None" or val == nil then return true end
        if val == "MB1" then return UserInput:IsMouseButtonPressed(Enum.UserInputType.MouseButton1) end
        if val == "MB2" then return UserInput:IsMouseButtonPressed(Enum.UserInputType.MouseButton2) end
        local ok, kc = pcall(function() return Enum.KeyCode[val] end)
        if ok and kc then return UserInput:IsKeyDown(kc) end
        return false
    end

    Library:Connect(RunService.RenderStepped, function()
        if Library.Unloaded then return end
        local cam = Library._camera()

        -- FOV circle render
        if fovCircle then
            if Library.Flags.FOV_Show and Library.Flags.Aim_Enabled then
                fovCircle.Radius = Library.Flags.Aim_FOV or 120
                fovCircle.Position = Vector2.new(cam.ViewportSize.X / 2, cam.ViewportSize.Y / 2)
                fovCircle.Color = Library.Flags.FOV_Rainbow and (Library.RainbowColor or Color3.new(1,1,1))
                    or Color3.fromRGB(Library.Flags.FOV_R or 255, Library.Flags.FOV_G or 255, Library.Flags.FOV_B or 255)
                fovCircle.Visible = true
            else
                fovCircle.Visible = false
            end
        end

        if not Library.Flags.Aim_Enabled or not keyHeld("Aim_Key") then
            currentTarget = nil
            if snapline then snapline.Visible = false end
            return
        end

        local target, part = selectTarget()
        currentTarget = target
        if not target or not part then
            if snapline then snapline.Visible = false end
            return
        end

        local char = target.Character
        local hum = char and char:FindFirstChildOfClass("Humanoid")
        if Library.Flags.Aim_VisibleCheck and not isVisible(part, char) then
            if snapline then snapline.Visible = false end
            return
        end

        local aimAt = predictPos(part, hum)
        local smooth = math.clamp(Library.Flags.Aim_Smoothness or 6, 1, 30)
        local goal = CFrame.new(cam.CFrame.Position, aimAt)
        cam.CFrame = cam.CFrame:Lerp(goal, 1 / smooth)

        -- Snapline
        if snapline and Library.Flags.FOV_ShowSnapline then
            local v, on = cam:WorldToViewportPoint(part.Position)
            if on and v.Z > 0 then
                snapline.From = Vector2.new(cam.ViewportSize.X / 2, cam.ViewportSize.Y)
                snapline.To = Vector2.new(v.X, v.Y)
                snapline.Color = fovCircle and fovCircle.Color or Color3.new(1,1,1)
                snapline.Visible = true
            else snapline.Visible = false end
        elseif snapline then
            snapline.Visible = false
        end
    end)

    ------------------------------------------------------------------
    -- Triggerbot — fires mouse when crosshair is over a valid enemy.
    -- Uses mouse1click/mouse1press where the executor exposes them.
    ------------------------------------------------------------------
    local mouse1click = mouse1click or (Input and Input.MouseClick)
    local mouse1press = mouse1press
    local mouse1release = mouse1release
    local function doTriggerClick()
        if type(mouse1press) == "function" and type(mouse1release) == "function" then
            mouse1press(); task.wait(); mouse1release()
        elseif type(mouse1click) == "function" then
            mouse1click()
        end
    end

    local trigBusy = false
    Library:Connect(RunService.Heartbeat, function()
        if Library.Unloaded or not Library.Flags.Trig_Enabled or trigBusy then return end
        if not keyHeld("Trig_Key") then return end
        if type(mouse1click) ~= "function" and type(mouse1press) ~= "function" then return end

        local cam = Library._camera()
        local center = Vector2.new(cam.ViewportSize.X / 2, cam.ViewportSize.Y / 2)
        local radius = Library.Flags.Trig_FOV or 6

        for _, plr in ipairs(Players:GetPlayers()) do
            if plr ~= LocalPlayer and aliveOf(plr) then
                if not (Library.Flags.Trig_TeamCheck and not isEnemy(plr)) then
                    local char = plr.Character
                    local part = char and hitboxPart(char)
                    if part then
                        local v, on = cam:WorldToViewportPoint(part.Position)
                        if on and v.Z > 0 and (Vector2.new(v.X, v.Y) - center).Magnitude <= radius then
                            if not Library.Flags.Trig_VisibleCheck or isVisible(part, char) then
                                trigBusy = true
                                task.delay((Library.Flags.Trig_Delay or 30) / 1000, function()
                                    -- re-confirm crosshair still on a target before firing
                                    pcall(doTriggerClick)
                                    trigBusy = false
                                end)
                                break
                            end
                        end
                    end
                end
            end
        end
    end)

    if type(mouse1click) ~= "function" and type(mouse1press) ~= "function" then
        Library:Notify("Triggerbot: executor lacks mouse1click/press; trigger disabled.", 6)
    end

    Library:OnUnload(function()
        if fovCircle then pcall(function() fovCircle.Visible = false end) end
        if snapline then pcall(function() snapline.Visible = false end) end
    end)
end

----------------------------------------------------------------------
--                    PHASE 4 — MOVEMENT / EXPLOITS
----------------------------------------------------------------------
do
    local getChar = Library._getChar

    local MTab = Tabs.Movement
    local flyGroup   = MTab:AddLeftGroupbox("Flight")
    local moveGroup  = MTab:AddLeftGroupbox("Movement")
    local exploitGrp = MTab:AddRightGroupbox("Exploits")
    local tpGroup    = MTab:AddRightGroupbox("Teleport")

    flyGroup:AddToggle("Fly_Enabled", { Text = "Enabled" })
        :AddKeyPicker("Fly_Key", { Default = "None", Mode = "Toggle", Text = "Fly", SyncToggleState = true })
    flyGroup:AddSlider("Fly_Speed", { Text = "Speed", Default = 50, Min = 10, Max = 500, Rounding = 0 })
    flyGroup:AddToggle("Fly_VerticalOnly", { Text = "Ignore camera pitch (level flight)" })
    flyGroup:AddToggle("FlyToMouse_Enabled", { Text = "Fly to mouse (hold key)" })
        :AddKeyPicker("FlyToMouse_Key", { Default = "F", Mode = "Hold", Text = "Fly to mouse" })

    moveGroup:AddToggle("Speed_Enabled", { Text = "Walk speed" })
    moveGroup:AddSlider("Speed_Value", { Text = "WalkSpeed", Default = 32, Min = 16, Max = 500, Rounding = 0 })
    moveGroup:AddToggle("JumpPower_Enabled", { Text = "Jump power" })
    moveGroup:AddSlider("JumpPower_Value", { Text = "JumpPower", Default = 50, Min = 50, Max = 500, Rounding = 0 })
    moveGroup:AddToggle("InfJump_Enabled", { Text = "Infinite jump" })
    moveGroup:AddToggle("Noclip_Enabled", { Text = "Noclip" })
        :AddKeyPicker("Noclip_Key", { Default = "None", Mode = "Toggle", Text = "Noclip", SyncToggleState = true })

    exploitGrp:AddToggle("AntiFling_Enabled", { Text = "Anti-fling" })
    exploitGrp:AddToggle("AntiAFK_Enabled", { Text = "Anti-AFK", Default = true })
    exploitGrp:AddToggle("Spinbot_Enabled", { Text = "Spinbot (HRP yaw spin)" })
    exploitGrp:AddSlider("Spinbot_Speed", { Text = "Spin speed", Default = 20, Min = 1, Max = 100, Rounding = 0 })
    exploitGrp:AddToggle("Freecam_Enabled", { Text = "Freecam (anchor body)" })

    tpGroup:AddButton("Teleport to closest player", function()
        local _, _, hrp = getChar()
        if not hrp then return Library:Notify("No character.") end
        local best, bestD = nil, math.huge
        for _, plr in ipairs(Players:GetPlayers()) do
            if plr ~= LocalPlayer and Library._alive(plr) then
                local _, _, ohrp = getChar(plr)
                if ohrp then
                    local d = (ohrp.Position - hrp.Position).Magnitude
                    if d < bestD then best, bestD = ohrp, d end
                end
            end
        end
        if best then hrp.CFrame = best.CFrame * CFrame.new(0, 0, 4) end
    end)
    tpGroup:AddButton("Teleport forward 25", function()
        local cam = Library._camera()
        local _, _, hrp = getChar()
        if hrp then hrp.CFrame = hrp.CFrame + cam.CFrame.LookVector * 25 end
    end)
    tpGroup:AddToggle("ClickTP_Enabled", { Text = "Click teleport (hold key + click)" })
        :AddKeyPicker("ClickTP_Key", { Default = "T", Mode = "Hold", Text = "Click TP" })

    ------------------------------------------------------------------
    -- Key-held helper (shared shape with Phase 3)
    ------------------------------------------------------------------
    local function keyHeld(flag)
        local opt = Library.Options[flag]
        if not opt then return false end
        local val = opt.Value
        if val == "None" or val == nil then return false end
        local ok, kc = pcall(function() return Enum.KeyCode[val] end)
        if ok and kc then return UserInput:IsKeyDown(kc) end
        return false
    end

    ------------------------------------------------------------------
    -- Flight (BodyVelocity + BodyGyro; reset cleanly when off)
    ------------------------------------------------------------------
    local bv, bg
    local function stopFly()
        if bv then bv:Destroy(); bv = nil end
        if bg then bg:Destroy(); bg = nil end
        local _, hum = getChar()
        if hum then pcall(function() hum.PlatformStand = false end) end
    end
    Library:Connect(RunService.RenderStepped, function()
        if Library.Unloaded then return end
        local char, hum, hrp = getChar()
        local flyOn = Library.Flags.Fly_Enabled and char and hrp and hum
        local toMouse = Library.Flags.FlyToMouse_Enabled and keyHeld("FlyToMouse_Key") and char and hrp

        if not (flyOn or toMouse) then
            if bv or bg then stopFly() end
            return
        end

        if not bv then
            bv = Instance.new("BodyVelocity")
            bv.MaxForce = Vector3.one * math.huge
            bv.Velocity = Vector3.zero
            bv.Parent = hrp
            bg = Instance.new("BodyGyro")
            bg.MaxTorque = Vector3.one * math.huge
            bg.P = 9e4
            bg.Parent = hrp
        end
        if hum then hum.PlatformStand = true end
        local cam = Library._camera()
        local speed = Library.Flags.Fly_Speed or 50

        if toMouse then
            -- Fly toward the 3D mouse hit (or far ray point).
            local mouseRay = cam:ViewportPointToRay(UserInput:GetMouseLocation().X, UserInput:GetMouseLocation().Y)
            local target = mouseRay.Origin + mouseRay.Direction * 500
            local dir = (target - hrp.Position)
            bv.Velocity = (dir.Magnitude > 1 and dir.Unit or Vector3.zero) * speed
            bg.CFrame = cam.CFrame
        else
            local dir = Vector3.zero
            local cf = cam.CFrame
            local look = Library.Flags.Fly_VerticalOnly
                and Vector3.new(cf.LookVector.X, 0, cf.LookVector.Z)
                or cf.LookVector
            if look.Magnitude > 0 then look = look.Unit end
            if UserInput:IsKeyDown(Enum.KeyCode.W) then dir += look end
            if UserInput:IsKeyDown(Enum.KeyCode.S) then dir -= look end
            if UserInput:IsKeyDown(Enum.KeyCode.A) then dir -= cf.RightVector end
            if UserInput:IsKeyDown(Enum.KeyCode.D) then dir += cf.RightVector end
            if UserInput:IsKeyDown(Enum.KeyCode.Space) then dir += Vector3.yAxis end
            if UserInput:IsKeyDown(Enum.KeyCode.LeftShift) then dir -= Vector3.yAxis end
            bv.Velocity = (dir.Magnitude > 0 and dir.Unit or Vector3.zero) * speed
            bg.CFrame = cf
        end
    end)

    ------------------------------------------------------------------
    -- Speed / Jump power
    ------------------------------------------------------------------
    Library:Connect(RunService.Heartbeat, function()
        if Library.Unloaded then return end
        local _, hum = getChar()
        if not hum then return end
        if Library.Flags.Speed_Enabled then
            hum.WalkSpeed = Library.Flags.Speed_Value or 32
        end
        if Library.Flags.JumpPower_Enabled then
            pcall(function()
                hum.UseJumpPower = true
                hum.JumpPower = Library.Flags.JumpPower_Value or 50
            end)
        end
    end)
    -- Reset speed/jump when toggled off.
    if Library.Toggles.Speed_Enabled then
        Library.Toggles.Speed_Enabled:OnChanged(function(v)
            if not v then local _, hum = getChar(); if hum then pcall(function() hum.WalkSpeed = 16 end) end end
        end)
    end

    ------------------------------------------------------------------
    -- Infinite jump
    ------------------------------------------------------------------
    Library:Connect(UserInput.JumpRequest, function()
        if Library.Unloaded or not Library.Flags.InfJump_Enabled then return end
        local _, hum = getChar()
        if hum then pcall(function() hum:ChangeState(Enum.HumanoidStateType.Jumping) end) end
    end)

    ------------------------------------------------------------------
    -- Noclip
    ------------------------------------------------------------------
    local clipped = {}
    Library:Connect(RunService.Stepped, function()
        if Library.Unloaded then return end
        if not Library.Flags.Noclip_Enabled then
            -- restore any parts we touched
            for part in pairs(clipped) do
                if part and part.Parent then pcall(function() part.CanCollide = true end) end
                clipped[part] = nil
            end
            return
        end
        local char = getChar()
        if not char then return end
        for _, p in ipairs(char:GetDescendants()) do
            if p:IsA("BasePart") and p.CanCollide then
                p.CanCollide = false
                clipped[p] = true
            end
        end
    end)

    ------------------------------------------------------------------
    -- Anti-fling (zero out absurd assembly velocities on own character)
    ------------------------------------------------------------------
    Library:Connect(RunService.Heartbeat, function()
        if Library.Unloaded or not Library.Flags.AntiFling_Enabled then return end
        local _, _, hrp = getChar()
        if hrp then
            local v = hrp.AssemblyLinearVelocity
            if v.Magnitude > 200 then
                pcall(function() hrp.AssemblyLinearVelocity = v.Unit * 50 end)
            end
            local av = hrp.AssemblyAngularVelocity
            if av.Magnitude > 30 then
                pcall(function() hrp.AssemblyAngularVelocity = Vector3.zero end)
            end
        end
    end)

    ------------------------------------------------------------------
    -- Spinbot (rotates HRP yaw; cosmetic / anti-aim-ish)
    ------------------------------------------------------------------
    local spinAngle = 0
    Library:Connect(RunService.RenderStepped, function(dt)
        if Library.Unloaded or not Library.Flags.Spinbot_Enabled then return end
        local _, _, hrp = getChar()
        if not hrp then return end
        spinAngle = (spinAngle + (Library.Flags.Spinbot_Speed or 20) * dt) % (math.pi * 2)
        pcall(function()
            hrp.CFrame = CFrame.new(hrp.Position) * CFrame.Angles(0, spinAngle, 0)
        end)
    end)

    ------------------------------------------------------------------
    -- Anti-AFK
    ------------------------------------------------------------------
    do
        local vu = game:FindService("VirtualUser")
        if vu then
            Library:Connect(LocalPlayer.Idled, function()
                if Library.Flags.AntiAFK_Enabled then
                    pcall(function()
                        vu:CaptureController()
                        vu:ClickButton2(Vector2.new())
                    end)
                end
            end)
        end
    end

    ------------------------------------------------------------------
    -- Freecam (anchor character, free camera with arrow/WASD via fly keys)
    ------------------------------------------------------------------
    local freecamAnchored = {}
    if Library.Toggles.Freecam_Enabled then
        Library.Toggles.Freecam_Enabled:OnChanged(function(on)
            local char = getChar()
            if not char then return end
            if on then
                for _, p in ipairs(char:GetDescendants()) do
                    if p:IsA("BasePart") and not p.Anchored then
                        p.Anchored = true
                        freecamAnchored[p] = true
                    end
                end
            else
                for p in pairs(freecamAnchored) do
                    if p and p.Parent then pcall(function() p.Anchored = false end) end
                    freecamAnchored[p] = nil
                end
            end
        end)
    end

    ------------------------------------------------------------------
    -- Click teleport (hold key, click to teleport to mouse hit)
    ------------------------------------------------------------------
    Library:Connect(UserInput.InputBegan, function(input, gpe)
        if Library.Unloaded or gpe then return end
        if input.UserInputType ~= Enum.UserInputType.MouseButton1 then return end
        if not (Library.Flags.ClickTP_Enabled and keyHeld("ClickTP_Key")) then return end
        local _, _, hrp = getChar()
        if not hrp then return end
        local cam = Library._camera()
        local ray = cam:ViewportPointToRay(UserInput:GetMouseLocation().X, UserInput:GetMouseLocation().Y)
        local params = RaycastParams.new()
        params.FilterType = Enum.RaycastFilterType.Exclude
        params.FilterDescendantsInstances = { LocalPlayer.Character }
        local hit = Workspace:Raycast(ray.Origin, ray.Direction * 5000, params)
        if hit then hrp.CFrame = CFrame.new(hit.Position + Vector3.new(0, 4, 0)) end
    end)

    ------------------------------------------------------------------
    -- Teardown: restore everything we changed.
    ------------------------------------------------------------------
    Library:OnUnload(function()
        stopFly()
        for part in pairs(clipped) do
            if part and part.Parent then pcall(function() part.CanCollide = true end) end
        end
        for p in pairs(freecamAnchored) do
            if p and p.Parent then pcall(function() p.Anchored = false end) end
        end
        local _, hum = getChar()
        if hum then pcall(function() hum.WalkSpeed = 16; hum.PlatformStand = false end) end
    end)
end

----------------------------------------------------------------------
--                       PHASE 5 — FUN / WACKY
----------------------------------------------------------------------
do
    local getChar = Library._getChar

    local FTab = Tabs.Fun
    local charGroup  = FTab:AddLeftGroupbox("Character")
    local trollGroup = FTab:AddLeftGroupbox("Troll (self)")
    local worldGroup = FTab:AddRightGroupbox("World")
    local effectGrp  = FTab:AddRightGroupbox("Effects")

    charGroup:AddToggle("Fun_Headless", { Text = "Tiny head" })
    charGroup:AddToggle("Fun_Giant", { Text = "Giant" })
    charGroup:AddSlider("Fun_Scale", { Text = "Body scale", Default = 100, Min = 20, Max = 500, Rounding = 0, Suffix = "%" })
    charGroup:AddToggle("Fun_Invisible", { Text = "Invisible body" })
    charGroup:AddToggle("Fun_Rainbow", { Text = "Rainbow body" })
    charGroup:AddButton("Ragdoll-ish (unanchor + fling up)", function()
        local _, _, hrp = getChar()
        if hrp then pcall(function() hrp.AssemblyLinearVelocity = Vector3.new(0, 80, 0) end) end
    end)

    trollGroup:AddToggle("Fun_Spin", { Text = "Spin character" })
    trollGroup:AddSlider("Fun_SpinSpeed", { Text = "Spin speed", Default = 30, Min = 1, Max = 200, Rounding = 0 })
    trollGroup:AddToggle("Fun_Float", { Text = "Float bob" })
    trollGroup:AddToggle("Fun_Earthquake", { Text = "Camera shake" })
    trollGroup:AddSlider("Fun_ShakeIntensity", { Text = "Shake intensity", Default = 5, Min = 1, Max = 50, Rounding = 0 })

    worldGroup:AddToggle("Fun_Fullbright", { Text = "Fullbright" })
    worldGroup:AddToggle("Fun_NoFog", { Text = "No fog" })
    worldGroup:AddSlider("Fun_TimeOfDay", { Text = "Time of day", Default = 14, Min = 0, Max = 24, Rounding = 0 })
    worldGroup:AddToggle("Fun_TimeControl", { Text = "Control time of day" })
    worldGroup:AddSlider("Fun_FOV", { Text = "Field of view", Default = 70, Min = 1, Max = 120, Rounding = 0 })
    worldGroup:AddToggle("Fun_FOVControl", { Text = "Control FOV" })

    effectGrp:AddToggle("Fun_Disco", { Text = "Disco lighting" })
    effectGrp:AddToggle("Fun_Trail", { Text = "Rainbow trail" })
    effectGrp:AddToggle("Fun_Gravity", { Text = "Low gravity" })
    effectGrp:AddSlider("Fun_GravityValue", { Text = "Gravity", Default = 50, Min = 0, Max = 196, Rounding = 0 })

    ------------------------------------------------------------------
    -- Helpers to remember & restore original state
    ------------------------------------------------------------------
    local origLighting = {
        Brightness = Lighting.Brightness,
        ClockTime = Lighting.ClockTime,
        FogEnd = Lighting.FogEnd,
        FogStart = Lighting.FogStart,
        Ambient = Lighting.Ambient,
        GlobalShadows = Lighting.GlobalShadows,
    }
    local origGravity = Workspace.Gravity
    local appliedTransparency = {}  -- part -> original transparency (invisible)
    local appliedColor = {}         -- part -> original color (rainbow)
    local trailObj

    local function restoreInvisible()
        for part, t in pairs(appliedTransparency) do
            if part and part.Parent then pcall(function() part.Transparency = t end) end
            appliedTransparency[part] = nil
        end
    end
    local function restoreColors()
        for part, c in pairs(appliedColor) do
            if part and part.Parent then pcall(function() part.Color = c end) end
            appliedColor[part] = nil
        end
    end

    ------------------------------------------------------------------
    -- Character scale (uses Humanoid body-scale values where present)
    ------------------------------------------------------------------
    local function applyScale()
        local char, hum = getChar()
        if not (char and hum) then return end
        local scale = (Library.Flags.Fun_Giant and 3) or ((Library.Flags.Fun_Scale or 100) / 100)
        for _, name in ipairs({ "BodyDepthScale", "BodyWidthScale", "BodyHeightScale" }) do
            local v = hum:FindFirstChild(name)
            if v and v:IsA("NumberValue") then pcall(function() v.Value = scale end) end
        end
        local hv = hum:FindFirstChild("HeadScale")
        if hv and hv:IsA("NumberValue") then
            pcall(function() hv.Value = Library.Flags.Fun_Headless and 0.3 or scale end)
        end
    end
    if Library.Toggles.Fun_Giant then Library.Toggles.Fun_Giant:OnChanged(applyScale) end
    if Library.Toggles.Fun_Headless then Library.Toggles.Fun_Headless:OnChanged(applyScale) end
    if Library.Options.Fun_Scale then Library.Options.Fun_Scale:OnChanged(applyScale) end

    ------------------------------------------------------------------
    -- Per-frame fun effects
    ------------------------------------------------------------------
    local spinAngle, bobT, discoT = 0, 0, 0
    local baseCamCF
    Library:Connect(RunService.RenderStepped, function(dt)
        if Library.Unloaded then return end
        local char, hum, hrp = getChar()

        -- Invisible body
        if Library.Flags.Fun_Invisible then
            if char then
                for _, p in ipairs(char:GetDescendants()) do
                    if p:IsA("BasePart") and p.Transparency < 1 then
                        if appliedTransparency[p] == nil then appliedTransparency[p] = p.Transparency end
                        p.Transparency = 1
                    end
                end
            end
        elseif next(appliedTransparency) then
            restoreInvisible()
        end

        -- Rainbow body
        if Library.Flags.Fun_Rainbow then
            local col = Library.RainbowColor or Color3.fromHSV((tick() % 5) / 5, 1, 1)
            if char then
                for _, p in ipairs(char:GetDescendants()) do
                    if p:IsA("BasePart") then
                        if appliedColor[p] == nil then appliedColor[p] = p.Color end
                        p.Color = col
                    end
                end
            end
        elseif next(appliedColor) then
            restoreColors()
        end

        -- Spin
        if Library.Flags.Fun_Spin and hrp then
            spinAngle = (spinAngle + (Library.Flags.Fun_SpinSpeed or 30) * dt) % (math.pi * 2)
            pcall(function() hrp.CFrame = CFrame.new(hrp.Position) * CFrame.Angles(0, spinAngle, 0) end)
        end

        -- Float bob
        if Library.Flags.Fun_Float and hrp then
            bobT = bobT + dt
            pcall(function()
                hrp.AssemblyLinearVelocity = Vector3.new(hrp.AssemblyLinearVelocity.X, math.sin(bobT * 3) * 8, hrp.AssemblyLinearVelocity.Z)
            end)
        end

        -- Camera shake
        local cam = Library._camera()
        if Library.Flags.Fun_Earthquake and cam then
            local i = (Library.Flags.Fun_ShakeIntensity or 5) / 10
            cam.CFrame = cam.CFrame * CFrame.new((math.random() - 0.5) * i, (math.random() - 0.5) * i, 0)
        end

        -- FOV control
        if Library.Flags.Fun_FOVControl and cam then
            cam.FieldOfView = Library.Flags.Fun_FOV or 70
        end

        -- Disco lighting
        if Library.Flags.Fun_Disco then
            discoT = discoT + dt
            if discoT > 0.15 then
                discoT = 0
                Lighting.Ambient = Color3.fromHSV(math.random(), 1, 1)
                Lighting.OutdoorAmbient = Color3.fromHSV(math.random(), 1, 1)
            end
        end
    end)

    ------------------------------------------------------------------
    -- Lighting / world toggles (apply on change; restore on unload)
    ------------------------------------------------------------------
    Library:Connect(RunService.Heartbeat, function()
        if Library.Unloaded then return end
        if Library.Flags.Fun_Fullbright then
            Lighting.Brightness = 2
            Lighting.ClockTime = 14
            Lighting.GlobalShadows = false
            Lighting.Ambient = Color3.fromRGB(178, 178, 178)
        end
        if Library.Flags.Fun_NoFog then
            Lighting.FogEnd = 1e6
            Lighting.FogStart = 1e6
        end
        if Library.Flags.Fun_TimeControl then
            Lighting.ClockTime = Library.Flags.Fun_TimeOfDay or 14
        end
        if Library.Flags.Fun_Gravity then
            Workspace.Gravity = Library.Flags.Fun_GravityValue or 50
        end
    end)

    -- Restore lighting/gravity once when their toggles are switched off.
    if Library.Toggles.Fun_Gravity then
        Library.Toggles.Fun_Gravity:OnChanged(function(on)
            if not on then pcall(function() Workspace.Gravity = origGravity end) end
        end)
    end
    local function restoreLighting()
        pcall(function()
            Lighting.Brightness    = origLighting.Brightness
            Lighting.ClockTime     = origLighting.ClockTime
            Lighting.FogEnd        = origLighting.FogEnd
            Lighting.FogStart      = origLighting.FogStart
            Lighting.Ambient       = origLighting.Ambient
            Lighting.GlobalShadows = origLighting.GlobalShadows
        end)
    end
    for _, fl in ipairs({ "Fun_Fullbright", "Fun_NoFog", "Fun_TimeControl" }) do
        if Library.Toggles[fl] then
            Library.Toggles[fl]:OnChanged(function(on)
                -- restore only if no other lighting override is still active
                if not on and not (Library.Flags.Fun_Fullbright or Library.Flags.Fun_NoFog or Library.Flags.Fun_TimeControl) then
                    restoreLighting()
                end
            end)
        end
    end

    ------------------------------------------------------------------
    -- Rainbow trail (HRP attachment trail)
    ------------------------------------------------------------------
    if Library.Toggles.Fun_Trail then
        Library.Toggles.Fun_Trail:OnChanged(function(on)
            local _, _, hrp = getChar()
            if on and hrp then
                if not trailObj or not trailObj.Parent then
                    local a0 = Instance.new("Attachment"); a0.Position = Vector3.new(0, 1, 0); a0.Parent = hrp
                    local a1 = Instance.new("Attachment"); a1.Position = Vector3.new(0, -1, 0); a1.Parent = hrp
                    trailObj = Instance.new("Trail")
                    trailObj.Attachment0 = a0
                    trailObj.Attachment1 = a1
                    trailObj.Lifetime = 1
                    trailObj.Color = ColorSequence.new({
                        ColorSequenceKeypoint.new(0, Color3.fromRGB(255, 0, 0)),
                        ColorSequenceKeypoint.new(0.5, Color3.fromRGB(0, 255, 0)),
                        ColorSequenceKeypoint.new(1, Color3.fromRGB(0, 0, 255)),
                    })
                    trailObj.Parent = hrp
                end
            elseif trailObj then
                pcall(function() trailObj:Destroy() end)
                trailObj = nil
            end
        end)
    end

    ------------------------------------------------------------------
    -- Reapply scale / re-add nothing-needed on respawn
    ------------------------------------------------------------------
    Library:Connect(LocalPlayer.CharacterAdded, function()
        task.wait(0.5)
        appliedTransparency = {}
        appliedColor = {}
        applyScale()
    end)

    ------------------------------------------------------------------
    -- Teardown: restore lighting, gravity, body, trail.
    ------------------------------------------------------------------
    Library:OnUnload(function()
        restoreInvisible()
        restoreColors()
        if trailObj then pcall(function() trailObj:Destroy() end) end
        restoreLighting()
        pcall(function() Workspace.Gravity = origGravity end)
        local cam = Library._camera()
        if cam then pcall(function() cam.FieldOfView = 70 end) end
    end)
end

----------------------------------------------------------------------
--                PHASE 6 — DROPDOWN / COLORPICKER WIDGETS
----------------------------------------------------------------------
-- These attach to the same Widgets table so every groupbox gains them, even
-- though they were declared after earlier widgets (groupbox metatables read
-- Library.Widgets live).

function Library.Widgets:AddDropdown(flag, info)
    info = info or {}
    local multi = info.Multi or false
    local Dropdown = {
        Type = "Dropdown", Flag = flag, Multi = multi,
        Values = info.Values or {},
        Value = multi and {} or (info.Default or nil),
        Callback = info.Callback,
    }
    if multi and type(info.Default) == "table" then
        for _, v in ipairs(info.Default) do Dropdown.Value[v] = true end
    end
    Library.Flags[flag] = Dropdown.Value

    rowFrame(self, 2)
    if info.Text then
        local lblRow = rowFrame(self, 14)
        local lbl = Library:Create("TextLabel", {
            BackgroundTransparency = 1, Size = UDim2.new(1, 0, 1, 0),
            Font = Library.FontFace, Text = info.Text,
            TextColor3 = Library.Theme.Font, TextSize = 13,
            TextXAlignment = Enum.TextXAlignment.Left, Parent = lblRow,
        })
        Library:AddToRegistry(lbl, { TextColor3 = "Font" })
    end

    local row = rowFrame(self, 22)
    local box = Library:Create("TextButton", {
        BackgroundColor3 = Library.Theme.MainLight, BorderSizePixel = 0,
        Size = UDim2.new(1, 0, 1, 0), AutoButtonColor = false,
        Font = Library.FontFace, Text = "", TextSize = 13, Parent = row,
    })
    Library:Corner(box, 4); Library:Stroke(box, "Outline")
    Library:AddToRegistry(box, { BackgroundColor3 = "MainLight" })
    local display = Library:Create("TextLabel", {
        BackgroundTransparency = 1, Position = UDim2.fromOffset(8, 0),
        Size = UDim2.new(1, -28, 1, 0), Font = Library.FontFace, Text = "--",
        TextColor3 = Library.Theme.Font, TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left, TextTruncate = Enum.TextTruncate.AtEnd,
        Parent = box,
    })
    Library:AddToRegistry(display, { TextColor3 = "Font" })
    local arrow = Library:Create("TextLabel", {
        BackgroundTransparency = 1, Position = UDim2.new(1, -20, 0, 0),
        Size = UDim2.fromOffset(16, 22), Font = Library.FontFace, Text = "+",
        TextColor3 = Library.Theme.Accent, TextSize = 16, Parent = box,
    })
    Library:AddToRegistry(arrow, { TextColor3 = "Accent" })

    -- Popup list (parented to ScreenGui so it floats over everything)
    local listOuter = Library:Create("Frame", {
        BackgroundColor3 = Library.Theme.Main, BorderSizePixel = 0,
        Visible = false, ZIndex = 50, Parent = Library.ScreenGui,
    })
    Library:Corner(listOuter, 4); Library:Stroke(listOuter, "Outline")
    Library:AddToRegistry(listOuter, { BackgroundColor3 = "Main" })
    local scroll = Library:Create("ScrollingFrame", {
        BackgroundTransparency = 1, BorderSizePixel = 0,
        Size = UDim2.new(1, -4, 1, -4), Position = UDim2.fromOffset(2, 2),
        CanvasSize = UDim2.new(), ScrollBarThickness = 3,
        ScrollBarImageColor3 = Library.Theme.Accent, ZIndex = 51, Parent = listOuter,
    })
    Library:Create("UIListLayout", { Padding = UDim.new(0, 2), SortOrder = Enum.SortOrder.LayoutOrder, Parent = scroll })
    Library.OpenedFrames[listOuter] = listOuter

    local MAX_VISIBLE = 8
    local function reposition()
        listOuter.Position = UDim2.fromOffset(box.AbsolutePosition.X, box.AbsolutePosition.Y + box.AbsoluteSize.Y + 2)
        listOuter.Size = UDim2.fromOffset(box.AbsoluteSize.X, math.min(#Dropdown.Values, MAX_VISIBLE) * 22 + 4)
    end
    Library:Connect(box:GetPropertyChangedSignal("AbsolutePosition"), reposition)

    function Dropdown:Display()
        if multi then
            local parts = {}
            for _, v in ipairs(Dropdown.Values) do
                if Dropdown.Value[v] then parts[#parts + 1] = v end
            end
            display.Text = #parts > 0 and table.concat(parts, ", ") or "--"
        else
            display.Text = Dropdown.Value ~= nil and tostring(Dropdown.Value) or "--"
        end
    end

    local buttons = {}
    function Dropdown:Rebuild()
        for _, b in ipairs(buttons) do pcall(function() b:Destroy() end) end
        table.clear(buttons)
        for _, v in ipairs(Dropdown.Values) do
            local opt = Library:Create("TextButton", {
                BackgroundColor3 = Library.Theme.MainLight, BorderSizePixel = 0,
                Size = UDim2.new(1, 0, 0, 20), AutoButtonColor = false,
                Font = Library.FontFace, Text = "  " .. tostring(v),
                TextColor3 = Library.Theme.Font, TextSize = 12,
                TextXAlignment = Enum.TextXAlignment.Left, ZIndex = 52, Parent = scroll,
            })
            local function refresh()
                local sel = multi and Dropdown.Value[v] or (Dropdown.Value == v)
                opt.TextColor3 = sel and Library.Theme.Accent or Library.Theme.Font
            end
            refresh()
            Library:Connect(opt.MouseButton1Click, function()
                if multi then
                    Dropdown.Value[v] = (not Dropdown.Value[v]) or nil
                else
                    Dropdown.Value = (Dropdown.Value == v) and (info.AllowNull and nil or Dropdown.Value) or v
                    listOuter.Visible = false; arrow.Text = "+"
                end
                Library.Flags[flag] = Dropdown.Value
                for _, b in ipairs(buttons) do
                    if b._refresh then b._refresh() end
                end
                Dropdown:Display()
                Library:SafeCallback(Dropdown.Callback, Dropdown.Value)
            end)
            opt._refresh = refresh
            buttons[#buttons + 1] = opt
        end
        scroll.CanvasSize = UDim2.fromOffset(0, #Dropdown.Values * 22)
        reposition()
    end

    function Dropdown:SetValues(v)
        Dropdown.Values = v or Dropdown.Values
        Dropdown:Rebuild(); Dropdown:Display()
    end
    function Dropdown:SetValue(v)
        if multi then
            local t = {}
            if type(v) == "table" then
                for key, on in pairs(v) do if on then t[key] = true end end
            end
            Dropdown.Value = t
        else
            Dropdown.Value = v
        end
        Library.Flags[flag] = Dropdown.Value
        for _, b in ipairs(buttons) do if b._refresh then b._refresh() end end
        Dropdown:Display()
        Library:SafeCallback(Dropdown.Callback, Dropdown.Value)
    end
    function Dropdown:OnChanged(fn) Dropdown.Callback = fn; Library:SafeCallback(fn, Dropdown.Value) end

    Library:Connect(box.MouseButton1Click, function()
        listOuter.Visible = not listOuter.Visible
        arrow.Text = listOuter.Visible and "-" or "+"
        if listOuter.Visible then reposition() end
    end)
    -- Close when clicking elsewhere.
    Library:Connect(UserInput.InputBegan, function(i)
        if i.UserInputType == Enum.UserInputType.MouseButton1 and listOuter.Visible then
            if not (Library:MouseOverFrame(listOuter) or Library:MouseOverFrame(box)) then
                listOuter.Visible = false; arrow.Text = "+"
            end
        end
    end)

    Dropdown:Rebuild(); Dropdown:Display()
    Library.Options[flag] = Dropdown
    return Dropdown
end

function Library.Widgets:AddColorPicker(flag, info)
    info = info or {}
    local default = info.Default or Color3.fromRGB(255, 140, 0)
    local Picker = { Type = "ColorPicker", Flag = flag, Value = default, Callback = info.Callback }
    Library.Flags[flag] = default

    local row = rowFrame(self, 18)
    local lbl = Library:Create("TextLabel", {
        BackgroundTransparency = 1, Size = UDim2.new(1, -28, 1, 0),
        Font = Library.FontFace, Text = info.Text or flag,
        TextColor3 = Library.Theme.Font, TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left, Parent = row,
    })
    Library:AddToRegistry(lbl, { TextColor3 = "Font" })
    local swatch = Library:Create("TextButton", {
        BackgroundColor3 = default, BorderSizePixel = 0, Text = "",
        Size = UDim2.fromOffset(22, 14), Position = UDim2.new(1, -24, 0, 2), Parent = row,
    })
    Library:Corner(swatch, 3); Library:Stroke(swatch, "Outline")

    -- Popup: H/S/V via three sliders (simple, dependency-free).
    local pop = Library:Create("Frame", {
        BackgroundColor3 = Library.Theme.Main, BorderSizePixel = 0,
        Size = UDim2.fromOffset(180, 96), Visible = false, ZIndex = 60, Parent = Library.ScreenGui,
    })
    Library:Corner(pop, 4); Library:Stroke(pop, "Outline")
    Library:AddToRegistry(pop, { BackgroundColor3 = "Main" })
    Library.OpenedFrames[pop] = pop

    local h, s, v = default:ToHSV()
    local function buildBar(name, yPos, getV, setV)
        local barLbl = Library:Create("TextLabel", {
            BackgroundTransparency = 1, Position = UDim2.fromOffset(8, yPos),
            Size = UDim2.fromOffset(20, 16), Font = Library.FontFace, Text = name,
            TextColor3 = Library.Theme.Font, TextSize = 12, ZIndex = 61, Parent = pop,
        })
        local bar = Library:Create("Frame", {
            BackgroundColor3 = Library.Theme.MainLight, BorderSizePixel = 0,
            Position = UDim2.fromOffset(32, yPos + 4), Size = UDim2.fromOffset(140, 8),
            ZIndex = 61, Parent = pop,
        })
        Library:Corner(bar, 3)
        local fill = Library:Create("Frame", {
            BackgroundColor3 = Library.Theme.Accent, BorderSizePixel = 0,
            Size = UDim2.new(getV(), 0, 1, 0), ZIndex = 62, Parent = bar,
        })
        Library:Corner(fill, 3)
        local dragging = false
        local function set()
            local w = bar.AbsoluteSize.X
            if w <= 0 then return end
            local rel = math.clamp((UserInput:GetMouseLocation().X - bar.AbsolutePosition.X) / w, 0, 1)
            setV(rel); fill.Size = UDim2.new(rel, 0, 1, 0)
        end
        Library:Connect(bar.InputBegan, function(i)
            if i.UserInputType == Enum.UserInputType.MouseButton1 then dragging = true; set() end
        end)
        Library:Connect(UserInput.InputChanged, function(i)
            if dragging and i.UserInputType == Enum.UserInputType.MouseMovement then set() end
        end)
        Library:Connect(UserInput.InputEnded, function(i)
            if i.UserInputType == Enum.UserInputType.MouseButton1 then dragging = false end
        end)
        return function(nv) fill.Size = UDim2.new(nv, 0, 1, 0) end
    end

    local function apply()
        Picker.Value = Color3.fromHSV(h, s, v)
        swatch.BackgroundColor3 = Picker.Value
        Library.Flags[flag] = Picker.Value
        Library:SafeCallback(Picker.Callback, Picker.Value)
    end
    buildBar("H", 6,  function() return h end, function(nv) h = nv; apply() end)
    buildBar("S", 36, function() return s end, function(nv) s = nv; apply() end)
    buildBar("V", 66, function() return v end, function(nv) v = nv; apply() end)

    function Picker:SetValueRGB(col)
        Picker.Value = col; h, s, v = col:ToHSV()
        swatch.BackgroundColor3 = col; Library.Flags[flag] = col
        Library:SafeCallback(Picker.Callback, col)
    end
    function Picker:OnChanged(fn) Picker.Callback = fn; Library:SafeCallback(fn, Picker.Value) end

    Library:Connect(swatch.MouseButton1Click, function()
        pop.Visible = not pop.Visible
        if pop.Visible then
            pop.Position = UDim2.fromOffset(swatch.AbsolutePosition.X - 158, swatch.AbsolutePosition.Y + 18)
        end
    end)
    Library:Connect(UserInput.InputBegan, function(i)
        if i.UserInputType == Enum.UserInputType.MouseButton1 and pop.Visible then
            if not (Library:MouseOverFrame(pop) or Library:MouseOverFrame(swatch)) then pop.Visible = false end
        end
    end)

    Library.Options[flag] = Picker
    return Picker
end

----------------------------------------------------------------------
--              PHASE 6 — CONFIG / THEMES / KEYBIND LIST
----------------------------------------------------------------------
do
    local STab = Tabs.Settings
    local cfgGroup   = STab:AddLeftGroupbox("Configuration")
    local themeGroup = STab:AddRightGroupbox("Theme")
    local uiGroup    = STab:AddRightGroupbox("Interface")

    local FOLDER = Library.Folder
    local CFG_DIR = FOLDER .. "/configs"
    local THEME_FILE = FOLDER .. "/theme.json"

    local function ensureFolders()
        if not HAS_FILES then return end
        pcall(function()
            if not isfolder(FOLDER) then makefolder(FOLDER) end
            if not isfolder(CFG_DIR) then makefolder(CFG_DIR) end
        end)
    end
    ensureFolders()

    ------------------------------------------------------------------
    -- Serialize / apply flags
    ------------------------------------------------------------------
    local function serializeValue(opt)
        local t = opt.Type
        if t == "Toggle" then return { t = "Toggle", v = opt.Value }
        elseif t == "Slider" then return { t = "Slider", v = opt.Value }
        elseif t == "Dropdown" then return { t = "Dropdown", v = opt.Value, multi = opt.Multi }
        elseif t == "ColorPicker" then
            local c = opt.Value
            return { t = "ColorPicker", v = { math.floor(c.R*255), math.floor(c.G*255), math.floor(c.B*255) } }
        elseif t == "KeyPicker" then return { t = "KeyPicker", v = opt.Value, mode = opt.Mode }
        end
    end

    local function collectConfig()
        local data = { toggles = {}, options = {} }
        for flag, tog in pairs(Library.Toggles) do
            data.toggles[flag] = serializeValue(tog)
        end
        for flag, opt in pairs(Library.Options) do
            local s = serializeValue(opt)
            if s then data.options[flag] = s end
        end
        return data
    end

    local function applyConfig(data)
        if type(data) ~= "table" then return end
        for flag, s in pairs(data.toggles or {}) do
            local tog = Library.Toggles[flag]
            if tog and type(s.v) == "boolean" then tog:SetValue(s.v) end
        end
        for flag, s in pairs(data.options or {}) do
            local opt = Library.Options[flag]
            if not opt then continue end
            if s.t == "Slider" and tonumber(s.v) then opt:SetValue(s.v)
            elseif s.t == "Dropdown" and opt.SetValue then opt:SetValue(s.v)
            elseif s.t == "ColorPicker" and type(s.v) == "table" and opt.SetValueRGB then
                opt:SetValueRGB(Color3.fromRGB(s.v[1] or 255, s.v[2] or 255, s.v[3] or 255))
            elseif s.t == "KeyPicker" and opt then
                opt.Value = s.v; opt.Mode = s.mode or opt.Mode
                Library.Flags[flag] = s.v
            end
        end
    end

    local function listConfigs()
        local out = {}
        if HAS_FILES and type(listfiles) == "function" then
            local ok, files = pcall(listfiles, CFG_DIR)
            if ok then
                for _, f in ipairs(files) do
                    local name = f:match("([^/\\]+)%.json$")
                    if name then out[#out + 1] = name end
                end
            end
        end
        return out
    end

    ------------------------------------------------------------------
    -- Config UI
    ------------------------------------------------------------------
    if not HAS_FILES then
        cfgGroup:AddLabel("File API unavailable — configs disabled.")
    else
        -- No Input widget in this build; configs are named via the dropdown list
        -- ("default" when none selected).
        local nameDD = cfgGroup:AddDropdown("Config_List", { Text = "Configs", Values = listConfigs(), AllowNull = true })
        cfgGroup:AddButton("Save (as 'default' or selected)", function()
            local name = Library.Flags.Config_List or "default"
            local ok, encoded = pcall(function() return HttpService:JSONEncode(collectConfig()) end)
            if not ok then return Library:Notify("Encode failed.") end
            pcall(writefile, CFG_DIR .. "/" .. name .. ".json", encoded)
            nameDD:SetValues(listConfigs())
            Library:Notify("Saved config '" .. name .. "'.")
        end)
        cfgGroup:AddButton("Load selected", function()
            local name = Library.Flags.Config_List
            if not name then return Library:Notify("Select a config first.") end
            local ok, raw = pcall(readfile, CFG_DIR .. "/" .. name .. ".json")
            if not ok then return Library:Notify("Read failed.") end
            local ok2, data = pcall(function() return HttpService:JSONDecode(raw) end)
            if not ok2 then return Library:Notify("Decode failed.") end
            applyConfig(data)
            Library:Notify("Loaded config '" .. name .. "'.")
        end)
        cfgGroup:AddButton("Delete selected", function()
            local name = Library.Flags.Config_List
            if not name or type(delfile) ~= "function" then return end
            pcall(delfile, CFG_DIR .. "/" .. name .. ".json")
            nameDD:SetValues(listConfigs())
            Library:Notify("Deleted '" .. name .. "'.")
        end)
        cfgGroup:AddButton("Refresh list", function() nameDD:SetValues(listConfigs()) end)
    end

    ------------------------------------------------------------------
    -- Theme manager (drives Library.Theme + the registry)
    ------------------------------------------------------------------
    local function applyThemeColors()
        Library.Theme.AccentDark = Color3.fromHSV(select(1, Library.Theme.Accent:ToHSV()), select(2, Library.Theme.Accent:ToHSV()), select(3, Library.Theme.Accent:ToHSV()) * 0.6)
        Library.Theme.MainLight = Color3.fromHSV(select(1, Library.Theme.Main:ToHSV()), select(2, Library.Theme.Main:ToHSV()), math.clamp(select(3, Library.Theme.Main:ToHSV()) * 1.6, 0, 1))
        Library.Theme.FontDark = Color3.fromHSV(select(1, Library.Theme.Font:ToHSV()), select(2, Library.Theme.Font:ToHSV()), select(3, Library.Theme.Font:ToHSV()) * 0.65)
        Library:UpdateTheme()
    end

    themeGroup:AddColorPicker("Theme_Accent", { Text = "Accent", Default = Library.Theme.Accent })
        :OnChanged(function(c) Library.Theme.Accent = c; applyThemeColors() end)
    themeGroup:AddColorPicker("Theme_Background", { Text = "Background", Default = Library.Theme.Background })
        :OnChanged(function(c) Library.Theme.Background = c; applyThemeColors() end)
    themeGroup:AddColorPicker("Theme_Main", { Text = "Main", Default = Library.Theme.Main })
        :OnChanged(function(c) Library.Theme.Main = c; applyThemeColors() end)
    themeGroup:AddColorPicker("Theme_Font", { Text = "Font", Default = Library.Theme.Font })
        :OnChanged(function(c) Library.Theme.Font = c; applyThemeColors() end)
    themeGroup:AddColorPicker("Theme_Outline", { Text = "Outline", Default = Library.Theme.Outline })
        :OnChanged(function(c) Library.Theme.Outline = c; applyThemeColors() end)

    themeGroup:AddButton("Save theme", function()
        if not HAS_FILES then return Library:Notify("No file API.") end
        local t = {}
        for _, k in ipairs({ "Accent", "Background", "Main", "Font", "Outline" }) do
            local c = Library.Theme[k]
            t[k] = { math.floor(c.R*255), math.floor(c.G*255), math.floor(c.B*255) }
        end
        pcall(writefile, THEME_FILE, HttpService:JSONEncode(t))
        Library:Notify("Theme saved.")
    end)

    -- Auto-load saved theme on startup.
    if HAS_FILES and pcall(isfile, THEME_FILE) and isfile(THEME_FILE) then
        pcall(function()
            local t = HttpService:JSONDecode(readfile(THEME_FILE))
            for _, k in ipairs({ "Accent", "Background", "Main", "Font", "Outline" }) do
                if t[k] then Library.Theme[k] = Color3.fromRGB(t[k][1], t[k][2], t[k][3]) end
            end
            applyThemeColors()
        end)
    end

    ------------------------------------------------------------------
    -- Interface options
    ------------------------------------------------------------------
    uiGroup:AddToggle("UI_ShowKeybinds", { Text = "Show keybind list", Default = true })
    uiGroup:AddToggle("UI_Watermark", { Text = "Show watermark", Default = true })
    uiGroup:AddButton("Unload Aurora", function() Library:Unload() end)

    ------------------------------------------------------------------
    -- Keybind list (on-screen, lists active KeyPickers)
    ------------------------------------------------------------------
    local kbFrame = Library:Create("Frame", {
        BackgroundColor3 = Library.Theme.Main, BorderSizePixel = 0,
        Position = UDim2.fromOffset(10, 200), Size = UDim2.fromOffset(150, 24),
        Visible = false, Parent = Library.ScreenGui,
    })
    Library:Corner(kbFrame, 4); Library:Stroke(kbFrame, "Outline")
    Library:AddToRegistry(kbFrame, { BackgroundColor3 = "Main" })
    local kbTitle = Library:Create("TextLabel", {
        BackgroundTransparency = 1, Size = UDim2.new(1, 0, 0, 20),
        Font = Library.FontBold, Text = "Keybinds", TextColor3 = Library.Theme.Accent,
        TextSize = 13, Parent = kbFrame,
    })
    Library:AddToRegistry(kbTitle, { TextColor3 = "Accent" })
    local kbList = Library:Create("Frame", {
        BackgroundTransparency = 1, Position = UDim2.fromOffset(6, 22),
        Size = UDim2.new(1, -12, 1, -24), Parent = kbFrame,
    })
    Library:Create("UIListLayout", { Padding = UDim.new(0, 2), SortOrder = Enum.SortOrder.LayoutOrder, Parent = kbList })
    Library:MakeDraggable(kbTitle, kbFrame)

    local kbLabels = {}
    Library:Connect(RunService.Heartbeat, function()
        if Library.Unloaded then return end
        if not Library.Flags.UI_ShowKeybinds then kbFrame.Visible = false; return end
        local count = 0
        for flag, opt in pairs(Library.Options) do
            if opt.Type == "KeyPicker" and opt.Value and opt.Value ~= "None" then
                count = count + 1
                local lab = kbLabels[flag]
                if not lab then
                    lab = Library:Create("TextLabel", {
                        BackgroundTransparency = 1, Size = UDim2.new(1, 0, 0, 16),
                        Font = Library.FontFace, TextColor3 = Library.Theme.Font, TextSize = 12,
                        TextXAlignment = Enum.TextXAlignment.Left, Parent = kbList,
                    })
                    Library:AddToRegistry(lab, { TextColor3 = "Font" })
                    kbLabels[flag] = lab
                end
                local active = opt.GetState and opt:GetState()
                lab.Text = ("[%s] %s"):format(tostring(opt.Value), flag)
                lab.TextColor3 = active and Library.Theme.Accent or Library.Theme.Font
            end
        end
        kbFrame.Visible = count > 0
        kbFrame.Size = UDim2.fromOffset(150, 24 + count * 18)
    end)

    ------------------------------------------------------------------
    -- Watermark (FPS + ping)
    ------------------------------------------------------------------
    local wmFrame = Library:Create("Frame", {
        BackgroundColor3 = Library.Theme.Main, BorderSizePixel = 0,
        Position = UDim2.fromOffset(10, 10), Size = UDim2.fromOffset(220, 24),
        Parent = Library.ScreenGui,
    })
    Library:Corner(wmFrame, 4); Library:Stroke(wmFrame, "Accent")
    Library:AddToRegistry(wmFrame, { BackgroundColor3 = "Main" })
    local wmText = Library:Create("TextLabel", {
        BackgroundTransparency = 1, Size = UDim2.new(1, -10, 1, 0), Position = UDim2.fromOffset(6, 0),
        Font = Library.FontFace, Text = "Aurora Universal", TextColor3 = Library.Theme.Font, TextSize = 13,
        TextXAlignment = Enum.TextXAlignment.Left, Parent = wmFrame,
    })
    Library:AddToRegistry(wmText, { TextColor3 = "Font" })
    Library:MakeDraggable(wmFrame, wmFrame)

    local frames, fps, acc = 0, 60, 0
    Library:Connect(RunService.RenderStepped, function(dt)
        if Library.Unloaded then return end
        frames = frames + 1; acc = acc + dt
        if acc >= 1 then fps = frames; frames = 0; acc = 0 end
        wmFrame.Visible = Library.Flags.UI_Watermark ~= false
        local ping = 0
        if Stats then
            pcall(function()
                ping = math.floor(Stats.Network.ServerStatsItem["Data Ping"]:GetValue())
            end)
        end
        wmText.Text = ("Aurora Universal | %d fps | %d ms"):format(fps, ping)
    end)

    Library:OnUnload(function()
        pcall(function() kbFrame:Destroy() end)
        pcall(function() wmFrame:Destroy() end)
    end)
end

Library:Notify("Aurora Universal fully loaded — all systems online.", 5)
