package config_test

import (
	"os"

	"github.com/catalogfi/tools/pkg/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type Config struct {
	Foo string `json:"foo"`
	Bar struct {
		InnerFoo string `json:"inner_foo"`
		InnerBar string `json:"inner_bar"`
	} `json:"bar"`
}

var _ = Describe("Config", func() {
	Context("Load from file", func() {
		It("should load the correct value from the file", func() {
			By("Create the config file")
			fileName := "config.json"
			data := `{
  "foo" : "1",
  "bar" :{
    "inner_foo" : "#ENV:TestKey",
    "inner_bar" : "3"
  }
}`
			Expect(os.WriteFile(fileName, []byte(data), 0644)).Should(Succeed())
			Expect(os.Setenv("TestKey", "2")).Should(Succeed())

			By("Load the config from file")
			var conf Config
			Expect(config.LoadFromFile("config.json", "", &conf)).Should(Succeed())

			By("Compare the value")
			Expect(conf.Foo).To(Equal("1"))
			Expect(conf.Bar.InnerFoo).To(Equal("2"))
			Expect(conf.Bar.InnerBar).To(Equal("3"))

			By("Remove the config file")
			Expect(os.Remove(fileName)).Should(Succeed())
		})
	})
})
