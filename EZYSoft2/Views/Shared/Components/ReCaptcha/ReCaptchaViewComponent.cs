using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using EZYSoft2.Helpers;
using EZYSoft2.Models;

namespace EZYSoft2.Views.Shared.Components.ReCaptcha
{
    public class ReCaptchaViewComponent : ViewComponent
    {
        private readonly ReCaptchaSettings _reCaptchaSettings;

        public ReCaptchaViewComponent(IOptions<ReCaptchaSettings> reCaptchaSettings)
        {
            _reCaptchaSettings = reCaptchaSettings.Value;
        }

        public IViewComponentResult Invoke()
        {
            return View("Default", _reCaptchaSettings.SiteKey);
        }
    }
}
