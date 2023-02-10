// -------------------------define-------------------------------
// -------------------------mian-------------------------------
Java.perform(() => {
	const cls = Java.use('com.ss.ttvideoengine.MediaPlayerWrapper');
	cls.setDataSource.overload('android.content.Context', 'android.net.Uri', 'java.util.Map').implementation = function (v0, uri, map) {
		const Uri = Java.use('android.net.Uri');
		send(uri.toString());
		uri = Uri.parse(data);
		send(v0.toString());
		let result = '';
		const keyset = map.keySet();
		const it = keyset.iterator();
		while (it.hasNext()) {
			const keystr = it.next().toString();
			const valuestr = map.get(keystr).toString();
			result += valuestr;
		}

		send(result);
		return this.setDataSource(v0, uri, map);
	};

	var data = 'mdl://id78/?rk=7121291048277593344&k=v0d00fg10000cb9ugh3c77u10c2r36k0_bytevc1_540p_1050133&u0=https%3A%2F%2Fv27-a.douyinvod.com%2Ff7b23028be6654b210b818c292c1612c%2F62e3695e%2Fvideo%2Ftos%2Fcn%2Ftos-cn-ve-15c001-alinc2%2Fe8356892580d4779a462d3913da9d919%2F%3Fa%3D1128%26ch%3D10010%26cr%3D3%26dr%3D0%26lr%3Dall%26cd%3D0%7C0%7C0%7C3%26cv%3D1%26br%3D1025%26bt%3D1025%26btag%3D80000%26cs%3D2%26ds%3D6%26ft%3D47IFAjjM95MxrKqoZmCTeK_ScoAwHX~pu6aVJEInv5RCPD%26mime_type%3Dvideo_mp4%26qs%3D14%26rc%3DaDo6NThpOmk7PGc6NGc8NUBpMzl1ZjQ6Zmt4ZTMzNGkzM0AxXzRgXjIuXmIxMS1eLjVhYSNoMC8tcjQwZDZgLS1kLWFzcw%3D%3D%26l%3D20220729115956010158116040170514A5&u1=https%3A%2F%2Fv26.douyinvod.com%2Fbf66f4799622d9ccc05c3ae581a85dc9%2F62e3695e%2Fvideo%2Ftos%2Fcn%2Ftos-cn-ve-15c001-alinc2%2Fe8356892580d4779a462d3913da9d919%2F%3Fa%3D1128%26ch%3D10010%26cr%3D3%26dr%3D0%26lr%3Dall%26cd%3D0%7C0%7C0%7C3%26cv%3D1%26br%3D1025%26bt%3D1025%26btag%3D80000%26cs%3D2%26ds%3D6%26ft%3D47IFAjjM95MxrKqoZmCTeK_ScoAwHX~pu6aVJEInv5RCPD%26mime_type%3Dvideo_mp4%26qs%3D14%26rc%3DaDo6NThpOmk7PGc6NGc8NUBpMzl1ZjQ6Zmt4ZTMzNGkzM0AxXzRgXjIuXmIxMS1eLjVhYSNoMC8tcjQwZDZgLS1kLWFzcw%3D%3D%26l%3D20220729115956010158116040170514A5&u2=https%3A%2F%2Fapi-hl.amemv.com%2Faweme%2Fv1%2Fplay%2F%3Fvideo_id%3Dv0d00fg10000cb9ugh3c77u10c2r36k0%26line%3D0%26file_id%3Dd2891da1074d49e8af175fa5c277b74e%26sign%3D46c441d52c5871b4061a2cc2587cc156%26is_play_url%3D1%26source%3DPackSourceEnum_PUBLISH%26pass-region%3D1%26pass-route%3D1%26iid%3D1535390967150711%26device_id%3D128016083857303%26ac%3Dwifi%26channel%3Ddy_tiny_sem_sogou_pz%26aid%3D1128%26app_name%3Daweme%26version_code%3D200600%26version_name%3D20.6.0%26device_platform%3Dandroid%26os%3Dandroid%26ssmix%3Da%26device_type%3DPixel%203%26device_brand%3Dgoogle%26language%3Dzh%26os_api%3D30%26os_version%3D11%26openudid%3D2cf99247acc688d4%26manifest_version_code%3D200601%26resolution%3D1080%2A2028%26dpi%3D440%26update_version_code%3D20609900%26_rticket%3D1659067289683%26package%3Dcom.ss.android.ugc.aweme%26cpu_support64%3Dtrue%26host_abi%3Darmeabi-v7a%26is_guest_mode%3D0%26app_type%3Dnormal%26minor_status%3D0%26appTheme%3Dlight%26need_personal_recommend%3D1%26is_android_pad%3D0%26ts%3D1659067287%26cdid%3Dfea73398-8399-4945-9f69-2191303fc6fb&ah=5b0';
});
