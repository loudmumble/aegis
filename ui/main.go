package main

import (
	"log"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"git.loudmumble.com/loudmumble/cuberoot-ui/theme"
	"git.loudmumble.com/loudmumble/cuberoot-ui/widgets"
)

func main() {
	go func() {
		w := new(app.Window)
		w.Option(app.Title("Aegis - Dashboard"))
		w.Option(app.Size(1200, 800))

		if err := run(w); err != nil {
			log.Fatal(err)
		}
	}()
	app.Main()
}

func run(w *app.Window) error {
	th := theme.New()
	var ops op.Ops

	navItems := []*widgets.NavItem{
		{Label: "Overview", Active: true},
		{Label: "Activity"},
		{Label: "Configuration"},
		{Label: "System"},
	}
	var actionBtn widget.Clickable

	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)

			layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(widgets.Topbar(th, "Aegis", nil)),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(widgets.Sidebar(th, navItems, 220)),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Top: th.Spacing.MD, Left: th.Spacing.MD, Right: th.Spacing.MD}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(widgets.Card(th, "Aegis Active", func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return material.Body1(th.Theme, "System operational").Layout(gtx)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.Inset{Top: th.Spacing.MD}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
													return widgets.Button(th, &actionBtn, "Execute Action", widgets.ButtonPrimary)(gtx)
												})
											}),
										)
									})),
								)
							})
						}),
					)
				}),
			)

			e.Frame(gtx.Ops)
		}
	}
}
