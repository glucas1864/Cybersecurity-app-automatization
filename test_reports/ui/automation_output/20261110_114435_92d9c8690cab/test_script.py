async def run_test(page, output_dir, page_url):
    try:
        await page.set_viewport_size({"width": 390, "height": 844})
        await page.wait_for_timeout(2500)
        print('URL:', page.url)
        print('Auth title visible:', await page.get_by_text('Análise com contexto.').is_visible())
        body_text = await page.locator('body').inner_text()
        print('Dark surface indicator:', 'SOC SENTINEL BLUE' in body_text)
        error_text = await page.evaluate("""() => { const errorElements = Array.from(document.querySelectorAll('.error, [class*='error'], [id*='error']')); return errorElements.map(el => el.textContent).join(', '); }""")
        print('Errors:', error_text or 'none')
        await page.screenshot(path='/app/test_reports/ui/automation_output/20261110_114435_92d9c8690cab/initial.jpeg', type="jpeg", quality=40, full_page=False)
    except Exception as e:
        print(f'FINDING: preview load failed: {e}')
        raise
