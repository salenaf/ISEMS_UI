"use strict";

const path = require("path");
const webpack = require("webpack");
const ExtractTextPlugin = require("extract-text-webpack-plugin");

const NODE_ENV = process.env.NODE_ENV || "development";

let bootstrapPath = path.join(__dirname, "node_modules/bootstrap/dist/css");

module.exports = {
    //место откуда берутся js файлы
    context: __dirname + "/public/js",

    //точки входа
    entry: {
        vendors: [
            "react",
            "reactDom",
            "reactBootstrap",
            "bootstrap",
            "bootstrapNotify",
            "bootstrapToggle",
            "bootstrapTokenfield",
            "bootstrapDatetimepicker",
            "datatablesNetBs",
            "select2",
            "md5js",
            "moment",
            "jquery",
            "socket.io-client",
            "socket.io-stream"
        ],
        authPage: "./authPage.js",
        mainPage: "./mainPage.js",
        headerMenu: "./headerMenu.jsx",
        settingUsersPage: "./settings/user/settingUsersPage.jsx",
        settingGroupsPage: "./settings/group/settingGroupsPage.jsx",
        settingOrganizationAndSourcesPage: "./settings/organizationsAndSources/organizationAndSources.jsx",
        settingRulesSAOPage: "./settings/RulesSOA/rulesSOA.jsx",
        networkInteractionMainHeader: "./moduleNetworkInteraction/networkInteractionMainHeader.jsx",
        managingAnalusisMainHeader: "./moduleAnalysis/pageManagingAnalysis.jsx", 
        drawingAlertsMessage: "./drawingAlertsMessage.jsx",
        common: "./common.js",
        styles: "./styles.js"
    },

    output: {
        //вывод обработанных webpack js файлов в указанную директорию
        path: path.resolve(__dirname, "public/dist"),

        //интернет путь до указанной директории
        publicPath: "/dist/",

        //шаблоны файлов, применяется при сборке основных файлов
        filename: "[name].js",

        //применяется при сборке файлов через require.ensure
        chunkFilename: "[id].js",

        //экспорт каждой точки входа должен попадать в переменную с соответствующем именем
        library: "[name]"
    },

    watch: NODE_ENV === "development",

    devtool: NODE_ENV === "development" ? "source-map" : null,

    devServer: {
        contentBase: path.join(__dirname, "public/dist"),
    },

    watchOptions: {
        poll: true,
        ignored: /node_modules/
    },

    resolve: {
        modules: ["node_modules", bootstrapPath],
        extensions: [".js", "jsx", ".css"],
        alias: {
            /*amcharts: 'amcharts/dist/amcharts/amcharts.js',
            amchartsSerial: 'amcharts/dist/amcharts/serial.js',
            amchartsExport: 'amcharts/dist/amcharts/plugins/export/export.min.js',*/
            "react": "react",
            "reactDom": "react-dom",
            "reactBootstrap": "react-bootstrap/dist/react-bootstrap.min.js",
            "bootstrap": "bootstrap/dist/js/bootstrap.min.js",
            "bootstrapNotify": "bootstrap-notify/bootstrap-notify.min.js",
            "bootstrapToggle": "bootstrap-toggle/js/bootstrap-toggle.min.js",
            "datatablesNetBs": "datatables.net-bs/js/dataTables.bootstrap.min.js",
            "bootstrapTokenfield": "bootstrap-tokenfield/dist/bootstrap-tokenfield.min.js",
            "bootstrapDatetimepicker": "bootstrap-datetimepicker/src/js/bootstrap-datetimepicker.js",
            "md5js": "crypto-js/md5.js",
            "moment": "moment/moment.js",
            "select2": "select2/dist/js/select2.full.min.js",
            "jquery": "jquery/dist/jquery.min.js",
            "socket.io-client": "socket.io-client/dist/socket.io.js",
            "socket.io-stream": "socket.io-stream/socket.io-stream.js"
        }
    },

    resolveLoader: {
        modules: ["node_modules"],
        extensions: [".js"],
        moduleExtensions: ["*-loader"]
    },

    /*externals: {
        jquery: '$'
    },*/

    /*optimization: {
        runtimeChunk: true,
        splitChunks: {
            cacheGroups: {
                commons: {
                    chunks: 'initial',
                    name: 'common',
                    test: 'common',
                    enforce: true,
                    minChunks: 2
                }
            }
        }
    },*/

    plugins: [
        //не собирать если есть ошибки
        new webpack.NoEmitOnErrorsPlugin(),

        //переменные окружения
        new webpack.DefinePlugin({
            NODE_ENV: JSON.stringify(NODE_ENV)
        }),

        /*
        //объединение повторяющихся скриптов в common.js только для webpack 3
        new webpack.optimize.CommonsChunkPlugin({ 
            name: 'common'
        }),*/

        //выносит все стили в отдельные файлы
        new ExtractTextPlugin("css/[id]_[name].css", { allChunks: true }),

        new webpack.ContextReplacementPlugin(/moment[\\/\\]locale$/, /ru|en-gb/),

        new webpack.optimize.OccurrenceOrderPlugin(true)
        /*new webpack.ProvidePlugin({
            $: 'jquery',
            jQuery: 'jquery',
            'window.$': 'jquery',
            'window.jQuery': 'jquery'
        })*/
    ],

    module: {
        rules: [{
            test: /\.js|jsx?$/, // определяем тип файлов
            exclude: /node_modules/, // исключаем из обработки папку node_modules
            loader: "babel-loader", // определяем загрузчик
            options: {
                presets: ["@babel/preset-env", "@babel/preset-react"] // используемые плагины
            }
        },
        {
            test: /\.js$/,
            exclude: /node_modules/,
            use: ["babel-loader"] //, 'eslint-loader']
        },
        {
            test: /\.css$/,
            use: ExtractTextPlugin.extract({
                fallback: "style-loader",
                use: ["css-loader"]
            })
        },
        {
            test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)(\?.*)?$/,
            include: /\/node_modules\//,
            use: [{
                loader: "file-loader",
                options: {
                    name: "[path][name].[ext]",
                    publicPath: "dist/",
                },
            }, ],
        },
        {
            test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)(\?.*)?$/,
            exclude: /\/node_modules\//,
            use: [{
                loader: "file-loader",
                options: {
                    name: "[path][name].[ext]",
                    publicPath: "dist/",
                },
            }, ],
        },
        {
            test: /bootstrap-tokenfield\/dist\/bootstrap-tokenfield\.min\.js/,
            loader: "imports-loader?this=>window&exports=>false&define=>false"
        },
        /*            {
                                        test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)(\?.*)?$/,
                                        include: /\/node_modules\//,
                                        loader: 'file-loader?name=[1]&regExp=node_modules/(.*)&publicPath=dist/'
                                    },
                                    {
                                        test: /\.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)(\?.*)?$/,
                                        exclude: /\/node_modules\//,
                                        loader: 'file-loader?name=[path][name].[ext]&publicPath=dist/'
                                    },*/
        {
            test: /\.ejs$/,
            loader: "ejs-loader"
        }
        ]
    }
};